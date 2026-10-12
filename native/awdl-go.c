// SPDX-License-Identifier: GPL-3.0-or-later
/* AX211 secondary nl80211 GO context. No association/authentication server.
 * Build against installed Linux nl80211 UAPI and libnl3. */
#include <errno.h>
#include <limits.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <poll.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static uint8_t mac[6] = {2,0x25,0,0xaa,0,1};
static const char ssid[] = "DIRECT-omdrop";
static struct nl_sock *sk;
static int family;
static unsigned go_id, mon_id, phy_id;
/* --freq: the GO's channel. 2437 (6) by default; 5745 (149) is where an
 * iPhone spends most of a transfer. */
static unsigned freq = 2437;
static uint8_t chan_num(void) { return freq == 2484 ? 14 : freq < 5000 ? (freq - 2407) / 5 : (freq - 5000) / 5; }
static volatile sig_atomic_t stopping;
static void stop(int n) { (void)n; stopping = 1; }
static struct nl_msg *message(int cmd, unsigned id) {
    struct nl_msg *m = nlmsg_alloc();
    if (!m || !genlmsg_put(m,0,0,family,0,0,cmd,0)) abort();
    if (id && nla_put_u32(m, NL80211_ATTR_IFINDEX,id)) abort();
    return m;
}
static int submit(struct nl_msg *m) {
    int e = nl_send_auto(sk,m); nlmsg_free(m);
    if (e >= 0) e = nl_wait_for_ack(sk);
    if (e < 0) fprintf(stderr,"netlink: %s (%d)\n",nl_geterror(e),e);
    return e;
}
static int set_up(const char *name) {
    int fd = socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    struct ifreq r = {0}; snprintf(r.ifr_name,sizeof(r.ifr_name),"%s",name);
    if (fd < 0) return -1;
    int e = ioctl(fd,SIOCGIFFLAGS,&r);
    if (!e) { r.ifr_flags |= IFF_UP; e = ioctl(fd,SIOCSIFFLAGS,&r); }
    if (e) perror("interface up");
    close(fd); return e;
}
static int create(const char *name, unsigned type, unsigned *owned) {
    if (if_nametoindex(name)) { fprintf(stderr,"name collision: %s\n",name); return -1; }
    struct nl_msg *m = message(NL80211_CMD_NEW_INTERFACE,0);
    if (nla_put_u32(m,NL80211_ATTR_WIPHY,phy_id) ||
        nla_put_string(m,NL80211_ATTR_IFNAME,name) ||
        nla_put_u32(m,NL80211_ATTR_IFTYPE,type) ||
        nla_put(m,NL80211_ATTR_MAC,6,mac)) abort();
    if (submit(m) < 0) return -1;
    *owned = if_nametoindex(name);
    if (!*owned) return -1;
    return set_up(name);
}
static size_t beacon(uint8_t *b) {
    memset(b,0,256); b[0]=0x80; memset(b+4,0xff,6);
    memcpy(b+10,mac,6); memcpy(b+16,mac,6);
    b[32]=100; b[34]=0x21; b[35]=4; /* ESS, short preamble, short slot */
    size_t n=36; b[n++]=0; b[n++]=sizeof(ssid)-1;
    memcpy(b+n,ssid,sizeof(ssid)-1); n+=sizeof(ssid)-1;
    const uint8_t rates[]={1,8,0x8c,0x12,0x98,0x24,0xb0,0x48,0x60,0x6c};
    memcpy(b+n,rates,sizeof(rates)); n+=sizeof(rates);
    b[n++]=3; b[n++]=1; b[n++]=chan_num();
    return n;
}
static size_t tail(uint8_t *b) {
    size_t n=0;
    b[n++]=45; b[n++]=26; memset(b+n,0,26);
    b[n+2]=0x1b; b[n+3]=0xff; n+=26; /* one-stream HT20, conservative caps */
    b[n++]=61; b[n++]=22; memset(b+n,0,22); b[n]=chan_num(); n+=22;
    const uint8_t p2p[]={221,18,0x50,0x6f,0x9a,9,2,2,0,0,1,3,6,0,2,0x25,0,0xaa,0,1};
    memcpy(b+n,p2p,sizeof(p2p)); memcpy(b+n+14,mac,6); n+=sizeof(p2p); return n;
}
static int start_ap(void) {
    uint8_t head[256], rest[128]; size_t hn=beacon(head),tn=tail(rest);
    const uint8_t basic[]={12,24,48};
    struct nl_msg *m=message(NL80211_CMD_START_AP,go_id);
    if (nla_put_u32(m,NL80211_ATTR_WIPHY_FREQ,freq) ||
        nla_put_u32(m,NL80211_ATTR_CHANNEL_WIDTH,NL80211_CHAN_WIDTH_20) ||
        nla_put_u32(m,NL80211_ATTR_CENTER_FREQ1,freq) ||
        nla_put_u32(m,NL80211_ATTR_BEACON_INTERVAL,100) ||
        nla_put_u32(m,NL80211_ATTR_DTIM_PERIOD,2) ||
        nla_put(m,NL80211_ATTR_SSID,sizeof(ssid)-1,ssid) ||
        nla_put_u32(m,NL80211_ATTR_HIDDEN_SSID,NL80211_HIDDEN_SSID_NOT_IN_USE) ||
        nla_put_u32(m,NL80211_ATTR_AUTH_TYPE,NL80211_AUTHTYPE_OPEN_SYSTEM) ||
        nla_put(m,NL80211_ATTR_BSS_BASIC_RATES,sizeof(basic),basic) ||
        nla_put_u8(m,NL80211_ATTR_AP_ISOLATE,1) ||
        nla_put(m,NL80211_ATTR_BEACON_HEAD,hn,head) ||
        nla_put(m,NL80211_ATTR_BEACON_TAIL,tn,rest)) abort();
    return submit(m);
}
/* AWDL peers as stations of the GO (`add MAC` / `del MAC` on stdin), so
 * mac80211 answers their ADDBA and the firmware block-acks their A-MPDUs:
 * unanswered, an iPhone sent one frame at a time at MCS 0 (~130 kB/s). The
 * patched iwlmvm (awdl_share 512) gives their block-ack frames the GO's
 * BSSID on the way in and AWDL's on the way out. */
static uint16_t next_aid = 1;
static int parse_mac(const char *t, uint8_t *m) {
    unsigned v[6]; char extra;
    if (sscanf(t,"%2x:%2x:%2x:%2x:%2x:%2x%c",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&extra)!=6) return -1;
    for (int j=0;j<6;j++) m[j]=(uint8_t)v[j];
    return 0;
}
static int station(const char *line) {
    char op[8], who[32]; uint8_t m[6];
    if (sscanf(line,"%7s %31s",op,who)!=2 || parse_mac(who,m)) return -1;
    if (!strcmp(op,"del")) {
        struct nl_msg *d=message(NL80211_CMD_DEL_STATION,go_id);
        if (nla_put(d,NL80211_ATTR_MAC,6,m)) abort();
        return submit(d);
    }
    if (strcmp(op,"add")) return -1;
    /* OFDM rates; HT: SGI20, 64 KiB A-MPDU, MCS 0-15. */
    const uint8_t rates[]={12,18,24,36,48,72,96,108};
    uint8_t ht[26]={0};
    ht[0]=0x20; ht[2]=0x1b; ht[3]=0xff; ht[4]=0xff;
    struct nl80211_sta_flag_update f={
        .mask=(1u<<NL80211_STA_FLAG_AUTHORIZED)|(1u<<NL80211_STA_FLAG_WME),
        .set=(1u<<NL80211_STA_FLAG_AUTHORIZED)|(1u<<NL80211_STA_FLAG_WME)};
    struct nl_msg *a=message(NL80211_CMD_NEW_STATION,go_id);
    if (nla_put(a,NL80211_ATTR_MAC,6,m) ||
        nla_put(a,NL80211_ATTR_STA_SUPPORTED_RATES,sizeof(rates),rates) ||
        nla_put_u16(a,NL80211_ATTR_STA_LISTEN_INTERVAL,1) ||
        nla_put_u16(a,NL80211_ATTR_STA_AID,next_aid) ||
        nla_put(a,NL80211_ATTR_HT_CAPABILITY,sizeof(ht),ht) ||
        nla_put(a,NL80211_ATTR_STA_FLAGS2,sizeof(f),&f)) abort();
    int e=submit(a);
    if (e>=0) next_aid = next_aid >= 2007 ? 1 : next_aid + 1;
    return e;
}
static int stations(void) {  /* -1 once stdin is closed */
    static char buf[256]; static size_t have;
    ssize_t r=read(0,buf+have,sizeof(buf)-1-have);
    if (r==0) return -1;
    if (r<0) return 0;
    have+=(size_t)r; buf[have]=0;
    char *nl;
    while ((nl=strchr(buf,'\n'))) {
        *nl=0;
        int e=station(buf);
        fprintf(stderr,"station %s %s\n", e<0 ? "FAIL" : "OK", buf);
        have-=(size_t)(nl+1-buf); memmove(buf,nl+1,have+1);
    }
    if (have>=sizeof(buf)-1) have=0;
    return 0;
}
static void remove_owned(const char *name,unsigned id) {
    if (!id || if_nametoindex(name)!=id) return;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    struct ifreq r={0}; snprintf(r.ifr_name,sizeof(r.ifr_name),"%s",name);
    int ours=fd>=0 && !ioctl(fd,SIOCGIFHWADDR,&r) && !memcmp(r.ifr_hwaddr.sa_data,mac,6);
    if(fd>=0) close(fd);
    if(ours) submit(message(NL80211_CMD_DEL_INTERFACE,id));
    else fprintf(stderr,"not removing interface whose identity changed: %s\n",name);
}
static int self_test(void) {
    uint8_t h[256],t[128]; size_t hn=beacon(h),tn=tail(t),n=36;
    if (memcmp(h+10,mac,6)||memcmp(h+16,mac,6)) return 1;
    while(n<hn) { if(n+2>hn||n+2+h[n+1]>hn) return 1; n+=2+h[n+1]; }
    n=0; while(n<tn) { if(n+2>tn||n+2+t[n+1]>tn) return 1; n+=2+t[n+1]; }
    printf("beacon self-test passed: head=%zu tail=%zu BSSID=02:25:00:aa:00:01\n",hn,tn);
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--self-test")) return self_test();
    int have_phy=0,have_mac=0;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--phy")&&i+1<argc) {
            char *end; const char *arg=argv[++i]; errno=0;
            unsigned long value=strtoul(arg,&end,10);
            if(!*arg||*arg=='-'||*end||errno||value>UINT_MAX) return 2;
            phy_id=(unsigned)value; have_phy=1;
        }
        else if(!strcmp(argv[i],"--mac")&&i+1<argc) {
            unsigned v[6]; char extra;
            if(sscanf(argv[++i],"%2x:%2x:%2x:%2x:%2x:%2x%c",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&extra)!=6 ||
               strlen(argv[i])!=17 || (v[0]&3)!=2) return 2;
            for(int j=0;j<6;j++) mac[j]=(uint8_t)v[j];
            have_mac=1;
        } else if(!strcmp(argv[i],"--freq")&&i+1<argc) {
            char *end; long f=strtol(argv[++i],&end,10);
            if(*end || !((f>=2412&&f<=2484)||(f>=5180&&f<=5885))) return 2;
            freq=(unsigned)f;
        } else { fprintf(stderr,"usage: %s --phy INDEX --mac LOCAL_MAC [--freq MHZ] | --self-test\n",argv[0]); return 2; }
    }
    if(!have_phy||!have_mac) return 2;
    if(geteuid()) { fprintf(stderr,"requires root\n"); return 1; }
    signal(SIGINT,stop); signal(SIGTERM,stop); signal(SIGALRM,stop);
    pid_t parent=getppid();
    if(prctl(PR_SET_PDEATHSIG,SIGTERM)||getppid()!=parent) return 1;
    sk=nl_socket_alloc();
    if(!sk||genl_connect(sk)<0||(family=genl_ctrl_resolve(sk,"nl80211"))<0) return 1;
    struct timeval timeout={3,0};
    setsockopt(nl_socket_get_fd(sk),SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    int result=1;
    if(create("awdlgo0",NL80211_IFTYPE_P2P_GO,&go_id)<0||stopping) goto out;
    if(start_ap()<0||stopping) goto out;
    if(create("mon0",NL80211_IFTYPE_MONITOR,&mon_id)<0||stopping) goto out;
    printf("READY go=%u monitor=%u\n",go_id,mon_id); fflush(stdout);
    int input=1;
    while(!stopping) {
        struct pollfd p={.fd=0,.events=POLLIN};
        if (!input) { struct timespec delay={1,0}; nanosleep(&delay,NULL); continue; }
        int n=poll(&p,1,1000);
        if (n>0 && (p.revents&(POLLIN|POLLHUP)) && stations()<0) input=0;
        else if (n>0 && (p.revents&(POLLERR|POLLNVAL))) input=0;
    }
    result=0;
out:
    remove_owned("mon0",mon_id);
    /* DEL_INTERFACE stops AP as well, and works after partial start failure. */
    remove_owned("awdlgo0",go_id);
    nl_socket_free(sk); return result;
}
