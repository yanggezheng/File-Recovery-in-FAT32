#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>  // for mmap
#include <sys/types.h> // for open
#include <sys/stat.h>  // for open
#include <fcntl.h>     // for open
#include <openssl/sha.h>
#define SHA_DIGEST_LENGTH 20
#pragma pack(push, 1)
typedef struct BootEntry
{
    unsigned char BS_jmpBoot[3];    // Assembly instruction to jump to boot code
    unsigned char BS_OEMName[8];    // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;  // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char BPB_SecPerClus;   // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;  // Size in sectors of the reserved area
    unsigned char BPB_NumFATs;      // Number of FATs
    unsigned short BPB_RootEntCnt;  // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;    // 16-bit value of number of sectors in file system
    unsigned char BPB_Media;        // Media type
    unsigned short BPB_FATSz16;     // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;   // Sectors per track of storage device
    unsigned short BPB_NumHeads;    // Number of heads in storage device
    unsigned int BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;    // A flag for FAT
    unsigned short BPB_FSVer;       // The major and minor version number
    unsigned int BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;      // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;   // Sector where backup copy of boot sector is located
    unsigned char BPB_Reserved[12]; // Reserved
    unsigned char BS_DrvNum;        // BIOS INT13h drive number
    unsigned char BS_Reserved1;     // Not used
    unsigned char BS_BootSig;       // Extended boot signature to identify if the next three values are valid
    unsigned int BS_VolID;          // Volume serial number
    unsigned char BS_VolLab[11];    // Volume label in ASCII. User defines when creating the file system
    unsigned char BS_FilSysType[8]; // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct DirEntry
{
    unsigned char DIR_Name[11];     // File name
    unsigned char DIR_Attr;         // File attributes
    unsigned char DIR_NTRes;        // Reserved
    unsigned char DIR_CrtTimeTenth; // Created time (tenths of second)
    unsigned short DIR_CrtTime;     // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;     // Created day
    unsigned short DIR_LstAccDate;  // Accessed day
    unsigned short DIR_FstClusHI;   // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;     // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;     // Written day
    unsigned short DIR_FstClusLO;   // Low 2 bytes of the first cluster address
    unsigned int DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

int printInvalid()
{
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    return 0;
}
int iCase(BootEntry **bootEntry)
{
    int numFATs = (*bootEntry)->BPB_NumFATs;
    int numBytsPerSec = (*bootEntry)->BPB_BytsPerSec;
    int numSecPerClus = (*bootEntry)->BPB_SecPerClus;
    int numRsvdSec = (*bootEntry)->BPB_RsvdSecCnt;
    printf("Number of FATs = %d\n", numFATs);
    printf("Number of bytes per sector = %d\n", numBytsPerSec);
    printf("Number of sectors per cluster = %d\n", numSecPerClus);
    printf("Number of reserved sectors = %d\n", numRsvdSec);
    return 0;
}
int lCase(BootEntry **bootEntry, void *data1)
{
    char *data = (char *)data1;
    // ！！！！！！！！！！
    char bootSectorString[90];
    memcpy(bootSectorString, data, 90);
    BootEntry *bootSector = (BootEntry *)bootSectorString;
    // Get the number of reserved sectors and the number of bytes per sector
    int numRsvdSec = (*bootEntry)->BPB_RsvdSecCnt;                  // 32
    int numBytsPerSec = (*bootEntry)->BPB_BytsPerSec;               // 512
    int clusterSize = numBytsPerSec * (*bootEntry)->BPB_SecPerClus; // 512.
    // Calculate the offset of the root directory in the disk
    int FATstart = numRsvdSec * numBytsPerSec;                                                                                           // 16384 where fat starts
    int numFATs = (*bootEntry)->BPB_NumFATs;                                                                                             // 2
    int numSecPerFAT = (*bootEntry)->BPB_FATSz32;                                                                                        // 4
    int root_dir_cluster = (*bootEntry)->BPB_RootClus;                                                                                   // 2
    int FATSize = ((bootSector->BPB_FATSz16) != 0) ? bootSector->BPB_FATSz16 * 2 : bootSector->BPB_FATSz32 * bootSector->BPB_BytsPerSec; // 2048
    // Calculate the size of a cluster, in bytes
    unsigned int dataStart = FATstart + FATSize * numFATs;
    int dirEntryStart = dataStart + (root_dir_cluster - 2) * clusterSize;                                // 20480
    unsigned int filePerEntry = clusterSize / 32;                                                        // 16
    unsigned int total_sectors = (*bootEntry)->BPB_TotSec16;                                             // 13856
    unsigned int data_area_size = (total_sectors - numSecPerFAT * numFATs - numRsvdSec) * numBytsPerSec; // 241664
    int numEntries = 0;
    int offset = dirEntryStart;
    int current = root_dir_cluster;
    for (;;)
    {
        for (int i = 0; i < filePerEntry; i++)
        {
            if (data[offset] == '\0' || (data[offset] & 0Xe5) == 0Xe5)
            {
                offset += sizeof(DirEntry);
                continue;
            }
            numEntries++;
            char each[sizeof(DirEntry)];
            memcpy(each, data + offset, sizeof(DirEntry));
            DirEntry *entries = (DirEntry *)each;
            char fileName[13];
            int j = 0;
            for (int i = 0; i < 8; i++)
            {
                if (data[offset + i] != ' ')
                {
                    fileName[j++] = data[offset + i];
                }
            }
            if (data[offset + 8] != ' ')
            {
                fileName[j++] = '.';
                for (int i = 8; i < 11; i++)
                {
                    if (data[offset + i] != ' ')
                    {
                        fileName[j++] = data[offset + i];
                    }
                }
            }
            if ((entries->DIR_Attr & 0x10) == 0x10)
            {
                fileName[j++] = '/';
            }
            fileName[j] = '\0';
            int firstCluster = entries->DIR_FstClusHI * 65536 + entries->DIR_FstClusLO;
            printf("%s (size = %u, starting cluster = %u)\n", fileName, entries->DIR_FileSize, firstCluster);
            offset += sizeof(DirEntry);
        }

        int *next = (int *)malloc(4);
        memcpy(next, data + FATstart + current * 4, 4);
        if (*next > 0X0ffffff7)
        {
            break;
        }
        else
        {
            offset = dataStart + (*next - 2) * clusterSize;
        }
        current = *next;
        free(next);
    }
    printf("Total number of entries = %d\n", numEntries);
    return 0;
}
int rCase(BootEntry **bootEntry, char *data1, char *fileName, int fd, char *SHA, int withS)
{
    char *data = (char *)data1;
    char bootSectorString[90];
    memcpy(bootSectorString, data, 90);
    BootEntry *bootSector = (BootEntry *)bootSectorString;
    // Get the number of reserved sectors and the number of bytes per sector
    int numRsvdSec = (*bootEntry)->BPB_RsvdSecCnt;                  // 32
    int numBytsPerSec = (*bootEntry)->BPB_BytsPerSec;               // 512
    int clusterSize = numBytsPerSec * (*bootEntry)->BPB_SecPerClus; // 512.
    // Calculate the offset of the root directory in the disk
    int FATstart = numRsvdSec * numBytsPerSec;    // 16384 where fat starts
    int numFATs = (*bootEntry)->BPB_NumFATs;      // 2
    int numSecPerFAT = (*bootEntry)->BPB_FATSz32; // 4
    int root_dir_cluster = (*bootEntry)->BPB_RootClus;
    char ENDOFFILE[] = {0xff, 0Xff, 0Xff, 0X0f};                                                                                         // 2
    int FATSize = ((bootSector->BPB_FATSz16) != 0) ? bootSector->BPB_FATSz16 * 2 : bootSector->BPB_FATSz32 * bootSector->BPB_BytsPerSec; // 2048
    // Calculate the size of a cluster, in bytes
    unsigned int dataStart = FATstart + FATSize * numFATs;
    int dirEntryStart = dataStart + (root_dir_cluster - 2) * clusterSize;                                // 20480
    unsigned int filePerEntry = clusterSize / 32;                                                        // 16
    unsigned int total_sectors = (*bootEntry)->BPB_TotSec16;                                             // 13856
    unsigned int data_area_size = (total_sectors - numSecPerFAT * numFATs - numRsvdSec) * numBytsPerSec; // 241664
    int offset = dirEntryStart;
    int current = root_dir_cluster;
    int count = 0, i, j, k, l, firstCluster = 0, fileSize, numPos = 0, firstByte, numClusters;
    char *fileName1 = malloc(12);
    strncpy(fileName1, fileName + 1, strlen(fileName) - 1);
    if (!withS)
    {
        for (;;)
        {
            for (i = 0; i < filePerEntry; i++)
            {
                if ((data[offset] & 0Xe5) == 0Xe5)
                {
                    char each[sizeof(DirEntry)];
                    memcpy(each, data + offset, sizeof(DirEntry));
                    DirEntry *entries = (DirEntry *)each;
                    char name[12];
                    int j = 0;
                    for (int i = 1; i < 8; i++)
                    {
                        if (data[offset + i] != ' ')
                        {
                            name[j++] = data[offset + i];
                        }
                    }
                    if (data[offset + 8] != ' ')
                    {
                        name[j++] = '.';
                        for (int i = 8; i < 11; i++)
                        {
                            if (data[offset + i] != ' ')
                            {
                                name[j++] = data[offset + i];
                            }
                        }
                    }
                    name[j] = '\0';
                    if (!strcmp(name, fileName1))
                    {
                        count++;
                    }
                }
                offset += sizeof(DirEntry);
                continue;
            }
            int *next = (int *)malloc(4);
            memcpy(next, data + FATstart + current * 4, 4);
            if (*next > 0X0ffffff7)
            {
                break;
            }
            else
            {
                offset = dataStart + (*next - 2) * clusterSize;
            }
            current = *next;
            free(next);
        }
        offset = dirEntryStart;
        current = bootSector->BPB_RootClus;
        if (count ==0)
        {
        printf("%s: file not found\n", fileName);
            return 0;
           
        }
        else if (count >1)
        {
             printf("%s: multiple candidates found\n", fileName);
            return 0;
        }
        for (;;)
        {
            for (i = 0; i < filePerEntry; i++)
            {
                if ((data[offset] & 0Xe5) == 0Xe5)
                {
                    char each[sizeof(DirEntry)];
                    memcpy(each, data + offset, sizeof(DirEntry));
                    DirEntry *entries = (DirEntry *)each;
                    char name[12];
                    int j = 0;
                    for (int i = 1; i < 8; i++)
                    {
                        if (data[offset + i] != ' ')
                        {
                            name[j++] = data[offset + i];
                        }
                    }
                    if (data[offset + 8] != ' ')
                    {
                        name[j++] = '.';
                        for (int i = 8; i < 11; i++)
                        {
                            if (data[offset + i] != ' ')
                            {
                                name[j++] = data[offset + i];
                            }
                        }
                    }
                    name[j] = '\0';
                    if (!strcmp(name, fileName1))
                    {
                        firstCluster = entries->DIR_FstClusHI * 65536 + entries->DIR_FstClusLO;
                        fileSize = entries->DIR_FileSize;
                        break;
                    }
                }
                offset += sizeof(DirEntry);
                continue;
            }

            int *next = (int *)malloc(4);
            memcpy(next, data + FATstart + current * 4, 4);
            if (*next > 0X0ffffff7)
            {
                break;
            }
            else
            {
                offset = dataStart + (*next - 2) * clusterSize;
            }
            current = *next;
            free(next);
        }
        free(fileName1);
        lseek(fd, offset, SEEK_SET);
        write(fd, fileName, 1);
        if (fileSize < clusterSize)
        {
            for (i = 0; i < numFATs; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    lseek(fd, FATstart + FATSize * i + 4 * firstCluster + j, SEEK_SET);
                    write(fd, ENDOFFILE + j, 1);
                }
            }
        }
        else
        {
            numClusters = (fileSize - 1) / clusterSize + 1;
            for (i = 0; i < numFATs; i++)
            {
                for (j = 0; j < numClusters - 1; j++)
                {
                    unsigned char byte[4];
                    
                    for (k = 3; k > -1; k--)
                    {
                        byte[k] = ((firstCluster + j + 1) >> (k * 8)) & 0xff;
                    }
                    lseek(fd, FATstart + FATSize * i + 4 * (firstCluster + j), SEEK_SET);
                    write(fd, byte, 4);
                }
                lseek(fd, FATstart + FATSize * i + 4 * (firstCluster + numClusters - 1), SEEK_SET);
                write(fd, ENDOFFILE, 4);
            }
        }
        printf("%s: successfully recovered\n", fileName);
        return 0;
    }
    else
    {
        int tracker[90];
        int posStart[90];
        int posSize[90];
        for (i = 0; i < 90; i++)
        {
            posSize[i] = -1;
            posStart[i] = -1;
        }

        for (;;)
        {
            for (i = 0; i < filePerEntry; i++)
            {
                if ((data[offset] & 0Xe5) == 0Xe5)
                {
                    char each[sizeof(DirEntry)];
                    memcpy(each, data + offset, sizeof(DirEntry));
                    DirEntry *entries = (DirEntry *)each;
                    char name[12];
                    j = 0;
                    for (i = 1; i < 8; i++)
                    {
                        if (data[offset + i] != ' ')
                        {
                            name[j++] = data[offset + i];
                        }
                    }
                    if (data[offset + 8] != ' ')
                    {
                        name[j++] = '.';
                        for (int i = 8; i < 11; i++)
                        {
                            if (data[offset + i] != ' ')
                            {
                                name[j++] = data[offset + i];
                            }
                        }
                    }
                    name[j] = '\0';
                    if (!strcmp(name, fileName1))
                    {
                        posStart[numPos] = entries->DIR_FstClusHI * 65536 + entries->DIR_FstClusLO;
                        posSize[numPos] = entries->DIR_FileSize;
                        tracker[numPos++] = offset;
                        posStart[numPos] = -1;
                        posSize[numPos] = -1;
                    }
                }
                offset += sizeof(DirEntry);
                continue;
            }
            int *next = (int *)malloc(4);
            memcpy(next, data + FATstart + current * 4, 4);
            if (*next > 0X0ffffff7)
            {
                break;
            }
            else
            {
                offset = dataStart + (*next - 2) * clusterSize;
            }
            current = *next;
            free(next);
        }
        for (i = 0; i < numPos; i++)
        {
            unsigned char md[SHA_DIGEST_LENGTH];
            SHA1(data + dataStart + (posStart[i] - 2) * clusterSize, posSize[i], md);
            char output[SHA_DIGEST_LENGTH*2+1];
            for (k = 0; k < SHA_DIGEST_LENGTH; k++)
            {
                snprintf(output + 2 * k, sizeof(output) - 2 * k, "%02x", md[k]);
            } // from stackOverFlow
            int match = 1;
            for (k = 0; k < SHA_DIGEST_LENGTH; k++)
            {
                if (output[k] != SHA[k])
                {
                    match = 0;
                    break;
                }
            }
            if (match)
            {
                break;
            }
        }
        if (numPos ==i)
        {
            printf("%s: file not found\n", fileName);
        }
        else
        {lseek(fd, tracker[i], SEEK_SET);
            write(fd, fileName, 1);
            if (posSize[i] < clusterSize)
        {
            if (posSize[i] != 0)
            {
                for ( j = 0; j < numFATs; j++)
                {
                    lseek(fd, FATstart + FATSize * j + 4 * posStart[i], SEEK_SET);
                    write(fd, ENDOFFILE, 4);
                }
            }
        }
        else
        {
             numClusters =  (posSize[i] - 1) / clusterSize+1;
            for ( k = 0; k < numFATs; k++)
            {
                for ( j = 0; j < numClusters - 1; j++)
                {
                    unsigned char bytes[4];
                    for (l = 3; l > -1; l--)
                    {
                        bytes[l] = ((posStart[i] + j + 1) >> (l * 8)) & 0xff;
                    }
                    lseek(fd, FATstart + FATSize * k + 4 * (posStart[i] + j), SEEK_SET);
                    write(fd, bytes, 4);
                }
                lseek(fd, FATstart + FATSize * k + 4 * (posStart[i] + numClusters - 1), SEEK_SET);
                write(fd, ENDOFFILE, 4);
            }
        }
        printf("%s: successfully recovered with SHA-1\n", fileName);
    }
        return 0;
    }
}
int RCase(BootEntry **bootEntry, char *fileName)
{
    printf("%s: file not found\n", fileName);
    return 0;
}

int main(int argc, char *argv[])
{
    char *fileName = malloc(13), *SHA = malloc(41);
    int ch, count = 2, flags[5], i;
    for (i = 0; i < 5; i++)
    {
        flags[i] = 0;
    }

    while ((ch = getopt(argc, argv, "ilr:R:s:")) != -1)
    {
        switch (ch)
        {
        case 'i':
            count++;
            flags[0] = 1;
            break;
        case 'l':
            count++;
            flags[1] = 1;
            break;
        case 'r':
            count += 2;
            flags[2] = 1;
            strcpy(fileName, optarg);
            break;
        case 'R':
            count += 2;
            flags[3] = 1;
            strcpy(fileName, optarg);
            break;
        case 's':
            count += 2;
            flags[4] = 1;
            strcpy(SHA, optarg);
            break;
        default:
            printInvalid();
        }
    }
    if (argc != count)
    {
        printInvalid();
        return 1;
    }
    struct stat sb;
    stat(argv[optind], &sb);
    int fd = open(argv[optind], O_RDWR);
    void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    BootEntry *bootEntry = (BootEntry *)data;
    char *a = malloc(2);
    a[0] = '0';
    if (flags[0])
    {
        iCase(&bootEntry);
    }
    if (flags[1])
    {
        lCase(&bootEntry, data);
    }
    if (flags[2])
    {
        if (flags[4])
        {
            rCase(&bootEntry, data, fileName, fd, SHA, 1);
        }
        else
        {
            rCase(&bootEntry, data, fileName, fd, a, 0);
        }
    }
    else if (flags[3])
    {
        RCase(&bootEntry, fileName);
    }
    free(fileName);
    close(fd);
    free(a);
    free(SHA);
    return 0;
}