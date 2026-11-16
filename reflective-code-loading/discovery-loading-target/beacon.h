/*
 * beacon.h — Minimal Beacon API header for BOF compatibility (Sliver/CS)
 */
#pragma once
#include <windows.h>

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* Beacon API prototypes — resolved by the BOF loader at runtime */
DECLSPEC_IMPORT void    BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char   *BeaconDataExtract(datap *parser, int *size);

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char   *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp *format, int value);

DECLSPEC_IMPORT void    BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char *data, int len);

DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);
