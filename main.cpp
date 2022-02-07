#include <iostream>
#include "wifi-jammer.hpp"
#include "iw/iwlib.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("syntax : wifi-jammer <interface>\n");
        printf("sample : wifi-jammer mon0\n");
        return -1;
    }

    char *dev = argv[1];

    Jammer jammer(dev);
    WiFi_Jammer(&jammer);

    return 0;
}