/*****************************************************************************
 * $File:   uci2dat.c
 *
 * $Author: Hua Shao
 * $Date:   Feb, 2014
 *
 * Boring, Boring, Boring, Boring, Boring........
 *
 *****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <memory.h>
#include <getopt.h>

#include <uci.h>


#ifdef OK
#undef OK
#endif
#define OK (0)

#ifdef NG
#undef NG
#endif
#define NG (-1)

#ifdef SHDBG
#undef SHDBG
#endif
#define SHDBG(...)   printf(__VA_ARGS__);
#define DEVNUM_MAX (4)
#define MBSSID_MAX (4)


#define FPRINT(fp, e, ...) \
            do {\
                char buffer[32] = {0}; \
                printf("%s(),%s=", __FUNCTION__, e->dat_key); \
                snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
                if (strlen(buffer) == 0) { \
                    fprintf(fp, e->defvalue?e->defvalue:""); \
                    printf("<def>"); \
                } \
                else { \
                    fprintf(fp, buffer); \
                    printf(buffer); \
                } \
                printf(", def=\"%s\"\n", e->defvalue?e->defvalue:""); \
            }while(0)


#define WIFI_UCI_FILE "/etc/config/wireless"

#define PARSE_UCI_OPTION(dst, src) \
    do { \
        src = NULL; \
        src = uci_lookup_option_string(uci_ctx, s, dst.uci_key); \
        if(src) { \
            strncpy(dst.value, src, sizeof(dst.value)); \
            printf("%s(),    %s=%s\n", __FUNCTION__, dst.uci_key, src); \
        } \
    }while(0)


struct _param;

typedef void (*ucihook)(FILE *,struct _param *, const char * devname);

typedef struct  _param{
    const char *    dat_key;
    const char *    uci_key;
    char            value[64];
    ucihook         hook;
    const char *    defvalue;
} param;

typedef struct _vif{
    param ssid;
    param authmode;
    param hidden;          /* Hidden SSID */
    param cipher;
    param key;
} vif;

typedef struct {
    char    devname[16];
    param * params;
    int     vifnum;
    vif     vifs[MBSSID_MAX];
} wifi_params;

void hooker(FILE * fp, param * p, const char * devname);

/* these are separated from CFG_ELEMENTS because they
   use a different represention structure.
*/
vif VIF = {
    .ssid       = {NULL, "ssid", {0}, NULL,  NULL},
    .authmode   = {NULL, "encryption", {0}, NULL,  NULL},
    .hidden     = {NULL, "hidden", {0}, NULL,  NULL},
    .cipher     = {NULL, "cipher", {0}, NULL,  NULL},
    .key        = {NULL, "key", {0}, NULL,  NULL},
};

param CFG_ELEMENTS[] = {
    /* Default configurations described in :
           MTK_Wi-Fi_SoftAP_Software_Programmming_Guide_v3.6.pdf
    */
    {"CountryRegion", "region", {0}, hooker,  ""},
    {"CountryRegionABand", "aregion", {0}, hooker, ""},
    {"CountryCode", "country", {0}, hooker, ""},
    {"BssidNum", NULL, {0}, hooker,  "1"},
    {"SSID1", NULL, {0}, hooker,  "OpenWrt"},
    {"SSID2", NULL, {0}, hooker,  NULL},
    {"SSID3", NULL, {0}, hooker,  NULL},
    {"SSID4", NULL, {0}, hooker,  NULL},
    {"WirelessMode", "wifimode", {0}, hooker,  "9"},
    {"TxRate", "txrate", {0}, hooker, "0"},
    {"Channel", "channel", {0}, hooker,  "0"},
    {"BasicRate", "basicrate", {0}, hooker, "15"},
    {"BeaconPeriod", "beacon", {0}, hooker,  "100"},
    {"DtimPeriod", "dtim", {0}, hooker,  "1"},
    {"TxPower", "txpoer", {0}, hooker,  "100"},
    {"DisableOLBC", NULL, {0}, NULL, "0"},
    {"BGProtection", "bgprotect", {0}, hooker,  "0"},
    {"TxAntenna", NULL, {0}, NULL, NULL},
    {"RxAntenna", NULL, {0}, NULL, NULL},
    {"TxPreamble", "txpreamble", {0}, hooker,  "0"},
    {"RTSThreshold", "rtsthres", {0}, hooker,  "2347"},
    {"FragThreshold", "fragthres", {0}, hooker,  "2346"},
    {"TxBurst", "txburst", {0}, hooker,  "1"},
    {"PktAggregate", "pktaggre", {0}, hooker,  "0"},
    {"TurboRate", NULL, {0}, NULL, "0"},
    {"WmmCapable", NULL, {0}, NULL, "0"},
    {"APSDCapable", NULL, {0}, NULL, "1"},
    {"DLSCapable", NULL, {0}, NULL, "0"},
    {"APAifsn", NULL, {0}, NULL, "3;7;1;1"},
    {"APCwmin", NULL, {0}, NULL, "4;4;3;2"},
    {"APCwmax", NULL, {0}, NULL, "6;10;4;3"},
    {"APTxop", NULL, {0}, NULL, "0;0;94;47"},
    {"APACM", NULL, {0}, NULL, "0;0;0;0"},
    {"BSSAifsn", NULL, {0}, NULL, "3;7;2;2"},
    {"BSSCwmin", NULL, {0}, NULL, "4;4;3;2"},
    {"BSSCwmax", NULL, {0}, NULL, "10;10;4;3"},
    {"BSSTxop", NULL, {0}, NULL, "0;0;94;47"},
    {"BSSACM", NULL, {0}, NULL, "0;0;0;0"},
    {"AckPolicy", NULL, {0}, NULL, "0;0;0;0"},
    {"NoForwarding", NULL, {0}, NULL, "0"},
    {"NoForwardingBTNBSSID", NULL, {0}, NULL, "0"},
    {"HideSSID", "hidden", {0}, hooker,  "0"},
    {"StationKeepAlive", NULL, {0}, NULL, "0"},
    {"ShortSlot", "shortslot", {0}, hooker,  "1"},
    {"AutoChannelSelect", "autoch", {0}, hooker, "2"},
    {"IEEE8021X", NULL, {0}, NULL, "0"},
    {"IEEE80211H", NULL, {0}, NULL, "0"},
    {"CSPeriod", NULL, {0}, NULL, "10"},
    {"WirelessEvent", NULL, {0}, NULL, "0"},
    {"IdsEnable", NULL, {0}, NULL, "0"},
    {"AuthFloodThreshold", NULL, {0}, NULL, "32"},
    {"AssocReqFloodThreshold", NULL, {0}, NULL, "32"},
    {"ReassocReqFloodThreshold", NULL, {0}, NULL, "32"},
    {"ProbeReqFloodThreshold", NULL, {0}, NULL, "32"},
    {"DisassocFloodThreshold", NULL, {0}, NULL, "32"},
    {"DeauthFloodThreshold", NULL, {0}, NULL, "32"},
    {"EapReqFooldThreshold", NULL, {0}, NULL, "32"},
    {"PreAuth", NULL, {0}, NULL, "0"},
    {"AuthMode", NULL, {0}, hooker,  "OPEN"},
    {"EncrypType", NULL, {0}, hooker,  "NONE"},
    {"RekeyInterval", NULL, {0}, NULL, "0"},
    {"PMKCachePeriod", NULL, {0}, NULL, "10"},
    {"WPAPSK1", NULL, {0}, hooker,  NULL},
    {"WPAPSK2", NULL, {0}, hooker,  NULL},
    {"WPAPSK3", NULL, {0}, hooker,  NULL},
    {"WPAPSK4", NULL, {0}, hooker,  NULL},
    {"DefaultKeyID", NULL, {0}, NULL, "1"},
    {"Key1Type", NULL, {0}, NULL, "0"},
    {"Key1Str1", NULL, {0}, NULL, NULL},
    {"Key1Str2", NULL, {0}, NULL, NULL},
    {"Key1Str3", NULL, {0}, NULL, NULL},
    {"Key1Str4", NULL, {0}, NULL, NULL},
    {"Key2Type", NULL, {0}, NULL, "0"},
    {"Key2Str1", NULL, {0}, NULL, NULL},
    {"Key2Str2", NULL, {0}, NULL, NULL},
    {"Key2Str3", NULL, {0}, NULL, NULL},
    {"Key2Str4", NULL, {0}, NULL, NULL},
    {"Key3Type", NULL, {0}, NULL, "0"},
    {"Key3Str1", NULL, {0}, NULL, NULL},
    {"Key3Str2", NULL, {0}, NULL, NULL},
    {"Key3Str3", NULL, {0}, NULL, NULL},
    {"Key3Str4", NULL, {0}, NULL, NULL},
    {"Key4Type", NULL, {0}, NULL, "0"},
    {"Key4Str1", NULL, {0}, NULL, NULL},
    {"Key4Str2", NULL, {0}, NULL, NULL},
    {"Key4Str3", NULL, {0}, NULL, NULL},
    {"Key4Str4", NULL, {0}, NULL, NULL},
    {"AccessPolicy0", NULL, {0}, NULL, "0"},
    {"AccessControlList0", NULL, {0}, NULL, NULL},
    {"AccessPolicy1", NULL, {0}, NULL, "0"},
    {"AccessControlList1", NULL, {0}, NULL, NULL},
    {"AccessPolicy2", NULL, {0}, NULL, "0"},
    {"AccessControlList2", NULL, {0}, NULL, NULL},
    {"AccessPolicy3", NULL, {0}, NULL, "0"},
    {"AccessControlList3", NULL, {0}, NULL, NULL},
    {"WdsEnable", NULL, {0}, NULL, "0"},
    {"WdsEncrypType", NULL, {0}, NULL, "NONE"},
    {"WdsList", NULL, {0}, NULL, NULL},
    {"Wds0Key", NULL, {0}, NULL, NULL},
    {"Wds1Key", NULL, {0}, NULL, NULL},
    {"Wds2Key", NULL, {0}, NULL, NULL},
    {"Wds3Key", NULL, {0}, NULL, NULL},
    {"RADIUS_Server", NULL, {0}, NULL, "192.168.2.3"},
    {"RADIUS_Port", NULL, {0}, NULL, "1812"},
    {"RADIUS_Key1", NULL, {0}, NULL, "ralink"},
    {"RADIUS_Key2", NULL, {0}, NULL, NULL},
    {"RADIUS_Key3", NULL, {0}, NULL, NULL},
    {"RADIUS_Key4", NULL, {0}, NULL, NULL},
    {"own_ip_addr", NULL, {0}, NULL, "192.168.5.234"},
    {"EAPifname", NULL, {0}, NULL, NULL},
    {"PreAuthifname", NULL, {0}, NULL, "br0"},
    {"HT_HTC", NULL, {0}, NULL, "0"},
    {"HT_RDG", "rdg", {0}, hooker,  "0"},
    {"HT_EXTCHA", NULL, {0}, NULL, "0"},
    {"HT_LinkAdapt", NULL, {0}, NULL, "0"},
    {"HT_OpMode", NULL, {0}, NULL, "0"},
    {"HT_MpduDensity", NULL, {0}, NULL, "5"},
    {"HT_BW", "bw", {0}, hooker,  "0"},
    {"VHT_BW", "vht_bw", {0}, hooker,  "1"},
    {"VHT_SGI", "vht_sgi", {0}, hooker,  "1"},
    {"VHT_STBC", "vht_stbc", {0}, hooker, "0"},
    {"VHT_BW_SIGNAL", "vht_bw_sig", {0}, hooker,  "0"},
    {"VHT_DisallowNonVHT", NULL, {0}, NULL, NULL},
    {"VHT_LDPC", "vht_ldpc", {0}, hooker, "1"},
    {"HT_AutoBA", NULL, {0}, NULL, "1"},
    {"HT_AMSDU", NULL, {0}, NULL, NULL},
    {"HT_BAWinSize", NULL, {0}, NULL, "64"},
    {"HT_GI", "gi", {0}, hooker,  "1"},
    {"HT_MCS", "ht_mcs", {0}, hooker, "33"},
    {"WscManufacturer", "wscmanufacturer", {0}, hooker, NULL},
    {"WscModelName", "wscmodelname", {0}, hooker, NULL},
    {"WscDeviceName", "wscdevicename", {0}, hooker, NULL},
    {"WscModelNumber", "wscmodelnumber", {0}, hooker, NULL},
    {"WscSerialNumber", "wscserialnumber", {0}, hooker, NULL},
    {"RadioOn", "radio", {0}, hooker,  "1"},

    /* Extra configurations found in 76x2e */
    {"FixedTxMode", NULL, {0}, NULL, "0"},
    {"AutoProvisionEn", NULL, {0}, NULL, "0"},
    {"FreqDelta", NULL, {0}, NULL, "0"},
    {"CarrierDetect", NULL, {0}, NULL, "0"},
    {"ITxBfEn", NULL, {0}, NULL, "0"},
    {"PreAntSwitch", NULL, {0}, NULL, "1"},
    {"PhyRateLimit", NULL, {0}, NULL, "0"},
    {"DebugFlags", NULL, {0}, NULL, "0"},
    {"ETxBfEnCond", NULL, {0}, NULL, "0"},
    {"ITxBfTimeout", NULL, {0}, NULL, "0"},
    {"ETxBfNoncompress", NULL, {0}, NULL, "0"},
    {"ETxBfIncapable", NULL, {0}, NULL, "0"},
    {"FineAGC", NULL, {0}, NULL, "0"},
    {"StreamMode", NULL, {0}, NULL, "0"},
    {"StreamModeMac0", NULL, {0}, NULL, ""},
    {"StreamModeMac1", NULL, {0}, NULL, ""},
    {"StreamModeMac2", NULL, {0}, NULL, ""},
    {"StreamModeMac3", NULL, {0}, NULL, ""},
    {"RDRegion", NULL, {0}, NULL, ""},
    {"DfsLowerLimit", NULL, {0}, NULL, "0"},
    {"DfsUpperLimit", NULL, {0}, NULL, "0"},
    {"DfsOutdoor", NULL, {0}, NULL, "0"},
    {"SymRoundFromCfg", NULL, {0}, NULL, "0"},
    {"BusyIdleFromCfg", NULL, {0}, NULL, "0"},
    {"DfsRssiHighFromCfg", NULL, {0}, NULL, "0"},
    {"DfsRssiLowFromCfg", NULL, {0}, NULL, "0"},
    {"DFSParamFromConfig", NULL, {0}, NULL, "0"},
    {"FCCParamCh0", NULL, {0}, NULL, ""},
    {"FCCParamCh1", NULL, {0}, NULL, ""},
    {"FCCParamCh2", NULL, {0}, NULL, ""},
    {"FCCParamCh3", NULL, {0}, NULL, ""},
    {"CEParamCh0", NULL, {0}, NULL, ""},
    {"CEParamCh1", NULL, {0}, NULL, ""},
    {"CEParamCh2", NULL, {0}, NULL, ""},
    {"CEParamCh3", NULL, {0}, NULL, ""},
    {"JAPParamCh0", NULL, {0}, NULL, ""},
    {"JAPParamCh1", NULL, {0}, NULL, ""},
    {"JAPParamCh2", NULL, {0}, NULL, ""},
    {"JAPParamCh3", NULL, {0}, NULL, ""},
    {"JAPW53ParamCh0", NULL, {0}, NULL, ""},
    {"JAPW53ParamCh1", NULL, {0}, NULL, ""},
    {"JAPW53ParamCh2", NULL, {0}, NULL, ""},
    {"JAPW53ParamCh3", NULL, {0}, NULL, ""},
    {"FixDfsLimit", NULL, {0}, NULL, "0"},
    {"LongPulseRadarTh", NULL, {0}, NULL, "0"},
    {"AvgRssiReq", NULL, {0}, NULL, "0"},
    {"DFS_R66", NULL, {0}, NULL, "0"},
    {"BlockCh", NULL, {0}, NULL, ""},
    {"GreenAP", NULL, {0}, NULL, "0"},
    {"PMKCachePeriod", NULL, {0}, NULL, "10"},
    {"WapiPsk1", NULL, {0}, NULL, ""},
    {"WapiPsk2", NULL, {0}, NULL, ""},
    {"WapiPsk3", NULL, {0}, NULL, ""},
    {"WapiPsk4", NULL, {0}, NULL, ""},
    {"WapiPsk5", NULL, {0}, NULL, ""},
    {"WapiPsk6", NULL, {0}, NULL, ""},
    {"WapiPsk7", NULL, {0}, NULL, ""},
    {"WapiPsk8", NULL, {0}, NULL, ""},
    {"WapiPskType", NULL, {0}, NULL, ""},
    {"Wapiifname", NULL, {0}, NULL, ""},
    {"WapiAsCertPath", NULL, {0}, NULL, ""},
    {"WapiUserCertPath", NULL, {0}, NULL, ""},
    {"WapiAsIpAddr", NULL, {0}, NULL, ""},
    {"WapiAsPort", NULL, {0}, NULL, ""},
    {"RekeyMethod", NULL, {0}, NULL, "DISABLE"},
    {"MeshAutoLink", NULL, {0}, NULL, "0"},
    {"MeshAuthMode", NULL, {0}, NULL, ""},
    {"MeshEncrypType", NULL, {0}, NULL, ""},
    {"MeshDefaultkey", NULL, {0}, NULL, "0"},
    {"MeshWEPKEY", NULL, {0}, NULL, ""},
    {"MeshWPAKEY", NULL, {0}, NULL, ""},
    {"MeshId", NULL, {0}, NULL, ""},
    {"HSCounter", "hscount", {0}, hooker, "0"},
    {"HT_BADecline", "ht_badec", {0}, hooker, "0"},
    {"HT_STBC", "ht_stbc", {0}, hooker, "0"},
    {"HT_LDPC", "ht_ldpc", {0}, hooker, "1"},
    {"HT_TxStream", "ht_txstream", {0}, hooker, "1"},
    {"HT_RxStream", "ht_rxstream", {0}, hooker, "1"},
    {"HT_PROTECT", "ht_protect", {0}, hooker, "1"},
    {"HT_DisallowTKIP", NULL, {0}, NULL, "0"},
    {"HT_BSSCoexistence", NULL, {0}, NULL, "0"},
    {"WscConfMode", "wscconfmode", {0}, hooker, "0"},
    {"WscConfStatus", "wscconfstatus", {0}, hooker, "2"},
    {"WCNTest", NULL, {0}, NULL, "0"},
    {"WdsPhyMode", NULL, {0}, NULL, ""},
    {"RADIUS_Acct_Server", NULL, {0}, NULL, ""},
    {"RADIUS_Acct_Port", NULL, {0}, NULL, "1813"},
    {"RADIUS_Acct_Key", NULL, {0}, NULL, ""},
    {"Ethifname", NULL, {0}, NULL, ""},
    {"session_timeout_interval", NULL, {0}, NULL, "0"},
    {"idle_timeout_interval", NULL, {0}, NULL, "0"},
    {"WiFiTest", NULL, {0}, NULL, "0"},
    {"TGnWifiTest", NULL, {0}, NULL, "0"},
    {"ApCliEnable", NULL, {0}, NULL, "0"},
    {"ApCliSsid", NULL, {0}, NULL, ""},
    {"ApCliBssid", NULL, {0}, NULL, ""},
    {"ApCliAuthMode", NULL, {0}, NULL, ""},
    {"ApCliEncrypType", NULL, {0}, NULL, ""},
    {"ApCliWPAPSK", NULL, {0}, NULL, ""},
    {"ApCliDefaultKeyID", NULL, {0}, NULL, "0"},
    {"ApCliKey1Type", NULL, {0}, NULL, "0"},
    {"ApCliKey1Str", NULL, {0}, NULL, ""},
    {"ApCliKey2Type", NULL, {0}, NULL, "0"},
    {"ApCliKey2Str", NULL, {0}, NULL, ""},
    {"ApCliKey3Type", NULL, {0}, NULL, "0"},
    {"ApCliKey3Str", NULL, {0}, NULL, ""},
    {"ApCliKey4Type", NULL, {0}, NULL, "0"},
    {"ApCliKey4Str", NULL, {0}, NULL, ""},
    {"EfuseBufferMode", NULL, {0}, NULL, "0"},
    {"E2pAccessMode", NULL, {0}, NULL, "2"},
    {"BW_Enable", NULL, {0}, NULL, "0"},
    {"BW_Root", NULL, {0}, NULL, "0"},
    {"BW_Priority", NULL, {0}, NULL, ""},
    {"BW_Guarantee_Rate", NULL, {0}, NULL, ""},
    {"BW_Maximum_Rate", NULL, {0}, NULL, ""},
//    {"RadioOff", "radio", {0}, hooker,  "0"}, // weird....

    /* add more configurations */
    {"AutoChannelSkipList", "autoch_skip", {0}, hooker, ""},
};

static struct uci_context * uci_ctx;
static struct uci_package * uci_wireless;
static wifi_params wifi_cfg[DEVNUM_MAX];


char * __get_value(char * datkey)
{
    int i;

    for(i=0;i<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); i++)
    {
        if(0 == strcmp(datkey, CFG_ELEMENTS[i].dat_key))
            return CFG_ELEMENTS[i].value;
    }
    return NULL;
}

char * __dump_all(void)
{
    int i, j;
    param * p = NULL;

    for(i=0; i<DEVNUM_MAX; i++)
    {
        if(strlen(wifi_cfg[i].devname) == 0) break;
        printf("%s     %-16s\t%-16s\t%-16s\t%-8s\t%s\n",
            wifi_cfg[i].devname, "[dat-key]", "[uci-key]", "[value]", "[hook]", "[default]");
        for(j=0;j<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); j++)
        {
                p = &wifi_cfg[i].params[j];
                printf("%s %2d. %-16s\t%-16s\t%-16s\t%-8s\t%s\n",
                    wifi_cfg[i].devname, j, p->dat_key, p->uci_key,
                    p->value[0]?p->value:"(null)", p->hook?"HOOK":"-", p->defvalue);
        }
    }
    return NULL;
}


void parse_dat(char * devname, char * datpath)
{
    FILE * fp = NULL;
    char buffer[128] = {0};
    char k[32] = {0};
    char v[32] = {0};
	int filelen = 0;
	int i = 0, n = 0;
	char * p = NULL;
	char * q = NULL;
    wifi_params * cfg = NULL;

    printf("API: %s(%s, %s)\n", __FUNCTION__, devname, datpath);

    for (i=0; i<DEVNUM_MAX; i++)
    {
        if(0 == strcmp(devname, wifi_cfg[i].devname))
            cfg = &wifi_cfg[i];
    }

    if(!cfg)
    {
        printf("%s(), device (%s) not found!\n", __FUNCTION__, devname);
        goto __error;
    }

    fp = fopen(datpath, "rb");
    if(!fp)
    {
        printf("%s() error: %s!\n", __FUNCTION__, strerror(errno));
        goto __error;
    }

	fseek(fp, 0, SEEK_END);
	filelen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("file len %d\n", filelen);

	memset(buffer, 0, sizeof(buffer));
	do
	{
		memset(buffer, 0, sizeof(buffer));
        p = fgets(buffer, sizeof(buffer), fp);
		if(!p) break;

		// skip empty lines
		while(*p == ' '|| *p == '\t') p++;
		if(*p == 0 || *p == '\r' || *p == '\n') continue;
		// skipe lines starts with "#"
		if(*p == '#') continue;

		// cut the \r\n tail!
		q = strchr(buffer, '\n'); if(q) *q = 0;
		q = strchr(buffer, '\r'); if(q) *q = 0;

		printf("%3d.\"%s\", ", i, buffer);
		i++;

		q = strstr(buffer, "=");
		if(!q) continue; // a valid line should contain "="

		*q = 0; q++; // split it!
		strncpy(k, p, sizeof(k));
		strncpy(v, q, sizeof(v));


		for ( n=0; n<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); n++)
		{
            if(0 == strcmp(CFG_ELEMENTS[n].dat_key, k))
            {
                strncpy(cfg->params[n].value, v, sizeof(CFG_ELEMENTS[n].value));
                break;
            }
		}
        if (n >= sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]))
            printf("!!! <%s> not supported\n", k);
        else
    		printf("<%s>=<%s>\n", k, v);

	}while(1);

#if 0
    /* dump and check */
    for ( n=0; n<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); n++)
    {
        if(strlen(cfg->params[n].value)>0)
            printf("inited: <%s>=<%s>\n", CFG_ELEMENTS[n].dat_key, cfg->params[n].value);
        else
            printf("empty : <%s>=<%s>\n", CFG_ELEMENTS[n].dat_key, cfg->params[n].value);
    }
#endif

__error:
    if(fp) fclose(fp);

    return;
}


void parse_uci(char * arg)
{
	struct uci_element *e   = NULL;
    const char * value = NULL;
    int i = 0;
    int cur_dev, cur_vif;

    printf("API: %s()\n", __FUNCTION__);
    if (!uci_wireless || !uci_ctx)
    {
        printf("%s() uci context not ready!\n", __FUNCTION__);
        return;
    }

    /* scan wireless devices ! */
    uci_foreach_element(&uci_wireless->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        const char * devname = NULL;

        if(0 == strcmp(s->type, "wifi-device"))
        {
            printf("%s(), wifi-device: %s\n", __FUNCTION__, s->e.name);
            for(cur_dev=0; cur_dev<DEVNUM_MAX; cur_dev++)
            {
                if(0 == strcmp(s->e.name, wifi_cfg[cur_dev].devname))
                    break;
            }

            if(cur_dev>=DEVNUM_MAX)
            {
                printf("%s(), device (%s) not found!\n", __FUNCTION__, s->e.name);
                break;
            }

            for( i = 0; i<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); i++)
            {
                if (CFG_ELEMENTS[i].uci_key)
                {
                    value = NULL;
                    value = uci_lookup_option_string(uci_ctx, s, CFG_ELEMENTS[i].uci_key);
                    if(value)
                    {
                        strncpy(wifi_cfg[cur_dev].params[i].value,
                            value, sizeof(CFG_ELEMENTS[i].value));
                        printf("%s(),    %s=%s\n", __FUNCTION__, CFG_ELEMENTS[i].uci_key, value);
                    }
                }
            }
        }
    }

    /* scan wireless network interfaces ! */
    uci_foreach_element(&uci_wireless->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        if(0 == strcmp(s->type, "wifi-iface"))
        {
            value = NULL; value = uci_lookup_option_string(uci_ctx, s, "device");
            for(cur_dev=0; cur_dev<DEVNUM_MAX; cur_dev++)
            {
                if(0 == strcmp(value, wifi_cfg[cur_dev].devname))
                    break;
            }
            if(cur_dev >= DEVNUM_MAX)
            {
                printf("%s(), device (%s) not found!\n", __FUNCTION__, value);
                break;
            }
            value = NULL; value = uci_lookup_option_string(uci_ctx, s, "ifname");
            printf("%s(), wifi-iface: %s\n", __FUNCTION__, value);

            cur_vif = wifi_cfg[cur_dev].vifnum;

            PARSE_UCI_OPTION(wifi_cfg[cur_dev].vifs[cur_vif].ssid, value);
            PARSE_UCI_OPTION(wifi_cfg[cur_dev].vifs[cur_vif].hidden, value);
            PARSE_UCI_OPTION(wifi_cfg[cur_dev].vifs[cur_vif].cipher, value);
            PARSE_UCI_OPTION(wifi_cfg[cur_dev].vifs[cur_vif].authmode, value);
            PARSE_UCI_OPTION(wifi_cfg[cur_dev].vifs[cur_vif].key, value);

            wifi_cfg[cur_dev].vifnum++;
        }
    }
    return;
}


void hooker(FILE * fp, param * p, const char * devname)
{
	struct uci_element *e   = NULL;
    int N = 0;
    int i = 0;

    //printf("API: %s(%s)\n", __FUNCTION__, p->element);

    if (!uci_wireless || !uci_ctx)
    {
        printf("%s() uci context not ready!\n", __FUNCTION__);
        return;
    }

    for(N=0; N<MBSSID_MAX; N++)
    {
        if(0 == strcmp(devname, wifi_cfg[N].devname))
            break;
    }
    if(N >= MBSSID_MAX)
    {
        printf("%s() device (%s) not found!\n", __FUNCTION__, devname);
        return;
    }

    if(0 == strncmp(p->dat_key, "SSID", 4))
    {
        i = atoi(p->dat_key+4)-1;
        if(i<0 || i >= MBSSID_MAX)
        {
            printf("%s() array index error, L%d\n", __FUNCTION__, __LINE__);
            return;
        }
        FPRINT(fp, p, wifi_cfg[N].vifs[i].ssid.value);
    }
    else if(0 == strcmp(p->dat_key, "BssidNum"))
    {
        FPRINT(fp, p, "%d", wifi_cfg[N].vifnum);
    }
    else if(0 == strcmp(p->dat_key, "EncrypType"))
    {
        for(i=0; i<wifi_cfg[N].vifnum; i++)
        {
            if (0 == strcasecmp(wifi_cfg[N].vifs[i].cipher.value, "psk2") ||
                0 == strcasecmp(wifi_cfg[N].vifs[i].cipher.value, "wpa2"))
                FPRINT(fp, p, "AES");
            else
                FPRINT(fp, p, "NONE");
            fprintf(fp, ";");
        }
    }
    else if(0 == strcmp(p->dat_key, "AuthMode"))
    {
        for(i=0; i<wifi_cfg[N].vifnum; i++)
        {
            if (0 == strcasecmp(wifi_cfg[N].vifs[i].authmode.value, "psk2") ||
                0 == strcasecmp(wifi_cfg[N].vifs[i].authmode.value, "wpa2"))
                FPRINT(fp, p, "WPA2PSK");
            else if (strstr(wifi_cfg[N].vifs[i].authmode.value, "mixed"))
                FPRINT(fp, p, "WPAPSKWPA2PSK");
            else if (0 == strcasecmp(wifi_cfg[N].vifs[i].authmode.value, "wep"))
                FPRINT(fp, p, "WEP");
            else if (0 == strcasecmp(wifi_cfg[N].vifs[i].authmode.value, "none") ||
                0 == strcasecmp(wifi_cfg[N].vifs[i].authmode.value, "open"))
                FPRINT(fp, p, "OPEN");
            else
                FPRINT(fp, p, "OPEN");
            fprintf(fp, ";");
        }

    }
    else if(0 == strncmp(p->dat_key, "WPAPSK", 6))
    {
        i = atoi(p->dat_key+6)-1;
        if(i<0 || i >= MBSSID_MAX)
        {
            printf("%s() array index error, L%d\n", __FUNCTION__, __LINE__);
            return;
        }
        FPRINT(fp, p, wifi_cfg[N].vifs[i].key.value);
    }
    else if(0 == strcmp(p->dat_key, "HideSSID"))
    {
        for(i=0; i<wifi_cfg[N].vifnum; i++)
        {
            if(i>0) FPRINT(fp, p, ";");
            FPRINT(fp, p, wifi_cfg[N].vifs[i].hidden.value[0]=='1'?"1":"0");
        }
    }
    else if(0 == strcmp(p->dat_key, "Channel"))
    {
        if(0 == strcmp(p->value, "auto"))
            FPRINT(fp, p, "0");
        else
            FPRINT(fp, p, p->value);
    }
    /* the rest part is quite simple! */
    else
    {
        FPRINT(fp, p, p->value);
    }

}


void gen_dat(char * devname, char * datpath)
{
    FILE       * fp = NULL;
    char buffer[64] = {0};
    int           i = 0;
    param       * p = NULL;
    wifi_params * cfg = NULL;

    printf("API: %s(%s, %s)\n", __FUNCTION__, devname, datpath);

    for (i=0; i<DEVNUM_MAX; i++)
    {
        if(0 == strcmp(devname, wifi_cfg[i].devname))
            cfg = &wifi_cfg[i];
    }
    if(!cfg)
    {
        printf("%s(), device (%s) not found!\n", __FUNCTION__, devname);
        return;
    }

    if (datpath)
    {
        fp = fopen(datpath, "wb");
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "mkdir -p /etc/Wireless/%s", cfg->devname);
        system(buffer);

        snprintf(buffer, sizeof(buffer), "/etc/Wireless/%s/%s.dat", cfg->devname, cfg->devname);
        // snprintf(buffer, sizeof(buffer), "/%s.dat", cfg->devname); //test only
        fp = fopen(buffer, "wb");
    }

    if(!fp)
    {
        printf("Failed to open %s, %s!\n", buffer, strerror(errno));
        return;
    }

    fprintf(fp, "# Generated by uci2dat\n");
    fprintf(fp, "# The word of \"Default\" must not be removed\n");
    fprintf(fp, "Default\n");


    for(i=0; i<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); i++)
    {
        p = &cfg->params[i];
        fprintf(fp, "%s=", p->dat_key);
        if(p->hook)
            p->hook(fp, p, cfg->devname);
        else if(strlen(p->value) > 0)
            fprintf(fp, p->value);
        else if(p->defvalue)
            fprintf(fp, p->defvalue);
        fprintf(fp, "\n");
    }

    fclose(fp);

    return;
}

void init_wifi_cfg(void)
{
	struct uci_element *e   = NULL;
    int i,j;

    printf("API: %s()\n", __FUNCTION__);

    for(i=0; i<DEVNUM_MAX; i++)
    {
        memset(&wifi_cfg[i], 0, sizeof(wifi_params));
        wifi_cfg[i].params = (param *)malloc(sizeof(CFG_ELEMENTS));
        memcpy(wifi_cfg[i].params, CFG_ELEMENTS, sizeof(CFG_ELEMENTS));

        for(j=0; j<MBSSID_MAX; j++)
            memcpy(&wifi_cfg[i].vifs[j], &VIF, sizeof(VIF));
    }

    uci_foreach_element(&uci_wireless->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        if(0 == strcmp(s->type, "wifi-device"))
        {
            printf("%s(), wifi-device: %s\n", __FUNCTION__, s->e.name);
            for(i=0; i<DEVNUM_MAX; i++)
            {
                if(0 == strlen(wifi_cfg[i].devname))
                {
                    strncpy(wifi_cfg[i].devname, s->e.name, sizeof(wifi_cfg[i].devname));
                    break;
                }
            }

            if(i>=DEVNUM_MAX)
            {
                printf("%s(), too many devices!\n", __FUNCTION__);
                break;
            }
        }
    }
}

void usage(void)
{
    int i, j;
    param * p = NULL;

    printf("uci2dat  -- a tool to translate openwrt wifi config (/etc/config/wireless)\n");
    printf("            into ralink driver dat.\n\n");
    printf("\nUsage:\n");
    printf("    uci2dat -d <dev-name> -f <dat-path>\n");

    printf("\nArguments:\n");
    printf("    -h              help\n");
    printf("    -d <dev-name>   device name, mt7620, eg.\n");
    printf("    -f <dat-path>   dat file path.\n");

    printf("\nSupported uci keywords:\n");
    printf("    %-16s\t%-16s\t%s\n", "[uci-key]", "[dat-key]", "[default]");
    for(i=0, j=0; i<sizeof(CFG_ELEMENTS)/sizeof(CFG_ELEMENTS[0]); i++)
    {
        p = &CFG_ELEMENTS[i];
        if(p->uci_key)
        {
            printf("%2d. %-16s\t%-16s\t%s\n",j, p->uci_key, p->dat_key, p->defvalue);
            j++;
        }
    }

    printf("%2d. %s\n", j++, VIF.ssid.uci_key);
    printf("%2d. %s\n", j++, VIF.authmode.uci_key);
    printf("%2d. %s\n", j++, VIF.hidden.uci_key);
    printf("%2d. %s\n", j++, VIF.cipher.uci_key);
    printf("%2d. %s\n", j++, VIF.key.uci_key);

}


int main(int argc, char ** argv)
{
	struct uci_element *e   = NULL;
    int opt = 0;
    int i = 0;
    char * dev = NULL;
    char * dat = NULL;
    int test = 0;

    while ((opt = getopt (argc, argv, "htf:d:")) != -1)
    {
    	switch (opt)
        {
            case 'f':
                dat = optarg;
                printf("---- datpath=\"%s\"\n", dat);
                break;
            case 'd':
                dev = optarg;
                printf("---- devname=\"%s\"\n", dev);
                break;
            case 't':
                test = 1;
                printf("---- TEST MODE ----\n");
                break;
            case 'h':
                usage();
                return OK;
            default:
                usage();
                return NG;
    	}
    }

    if (!uci_ctx)
    {
        uci_ctx = uci_alloc_context();
    }
    else
    {
        uci_wireless = uci_lookup_package(uci_ctx, "wireless");
        if (uci_wireless)
            uci_unload(uci_ctx, uci_wireless);
    }

    if (uci_load(uci_ctx, "wireless", &uci_wireless))
    {
        return NG;
    }

#if 0
	uci_foreach_element(&uci_wireless->sections, e)
    {
		struct uci_section *s   = uci_to_section(e);
        struct uci_element *ee  = NULL;
        struct uci_option  *o   = NULL;

        printf("%s() === %s\n", __FUNCTION__, s->type);
        uci_foreach_element(&s->options, ee)
        {
            o = uci_to_option(ee);
            printf("%s() : <%s>=<%s>\n", __FUNCTION__, ee->name, o->v.string);
        }
    }
#endif

    init_wifi_cfg();

    if(dev && dat)
    {
        parse_dat(dev, dat);
        parse_uci(NULL);
    }

    if(test)
        __dump_all();
    else if(dev && dat)
        gen_dat(dev, dat);
    else
        usage();

    uci_unload(uci_ctx, uci_wireless);
    return OK;
}




