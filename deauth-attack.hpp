#ifndef _DEAUTH_ATTACK_HPP_
#define _DEAUTH_ATTACK_HPP_

#include <iostream>
#include <regex>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

#define FALSE 0
#define TRUE 1

typedef bool                BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        DWORD;
typedef unsigned long long  QWORD;
typedef unsigned long       ULONG_PTR;

class mac
{
private:
    BYTE address[6] = { 0, };

public:
    mac();
    mac(const BYTE *MAC_Array);
    mac(const char *MAC_String);
    BYTE *toByteArray();
    std::string toString();
};

class DeauthAttack
{
private:
    char *dev = NULL;
    pcap_t *pcap = NULL;
    mac BSSID;
    mac STATION;
    int channel = 0;
    std::vector<int> Channels;

    void GetChannels();
    void SetChannel(int channel);
    void SearchChannel();
    void SearchBeacon(int channel);
    bool SendDeauthPacket(BYTE *BSSID);
    bool SendDeauthPacket(BYTE *src, BYTE *dst);

public:
    DeauthAttack(char *dev);
    // bool SetBSSID(char *BSSID);
    // bool SetBSSID(std::string BSSID);
    // bool SetBSSID(BYTE *BSSID);
    bool SetBSSID(mac BSSID);
    bool SetSTATION(mac STATION);
    void SendDeauthPacket(bool Broadcast);
    void SendDeauthPacket(bool Broadcast, int Channel);
    void SendAuthPacket();
    void SendAuthPacket(int Channel);
};

typedef struct _TaggedParameter
{
    BYTE TagNumber;
    BYTE TagLength;
} TaggedParameter;

typedef struct _Channel
{
    TaggedParameter Tag;
    BYTE Channel;
} Channel;

#pragma pack(push, 1)
typedef struct _Radiotap
{
    BYTE HeaderRevision;
    BYTE HeaderPad;
    WORD HeaderLength;
    QWORD PresentFlags;
    BYTE Flags;
    BYTE DataRate;
    WORD ChannelFrequency;
    WORD ChannelFlags;
    BYTE AntennaSignal1;
    BYTE Reserved;
    WORD RXFlags;
    BYTE AntennaSignal2;
    BYTE Antenna;
} Radiotap;
#pragma pack(pop)

typedef struct _BeaconFrame
{
    union
    {
        struct
        {
            WORD Version : 2;
            WORD Type    : 2;
            WORD Subtype : 4;
        };
        WORD FrameControlField;
    };
    WORD Duration;
    union
    {
        BYTE ReceiverMac[6];
        BYTE DestinationMac[6];
    };
    union
    {
        BYTE TransmitterMac[6];
        BYTE SourceMac[6];
    };
    BYTE BSSID[6];
    WORD FragmentNumber : 4;
    WORD SequenceNumber : 12;

    BOOL IsBeacon();
} BeaconFrame;

#pragma pack(push, 4)
typedef struct _WirelessManagement
{
    struct
    {
        QWORD Timestamp;
        WORD BeaconInterval;
        WORD CapabilitiesInformation;
    } Fixed;
    BYTE TaggedData[1];

    Channel *GetChannel();
} WirelessManagement;
#pragma pack(pop)

typedef struct _IEEE_80211
{
    Radiotap Radio;
    BeaconFrame Beacon;
    WirelessManagement Management;
} IEEE_80211;

#endif