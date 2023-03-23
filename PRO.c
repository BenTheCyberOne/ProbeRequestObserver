/*
Author: BenTheCyberOne
Current Version: 1.1.0
Blog: https://thissiteissafe.com

Compile Instructions:
gcc PRO.c -o PRO -lpcap -lsqlite3

*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sqlite3.h>
#include <time.h>
//Channel hopping interval
#define HOP_INT 3

//Number of request records to show
#define DISP_NUM 20


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void displayData(const u_char* packet, int count, sqlite3 *db);
int displayall_callback(void *NotUsed, int num_cols, char **col_vals, char **col_names);

//Struct for pcap_loop() packet handler args (this passes the db object so we only have to open it once)
struct pcap_args {
    sqlite3 *db;
};


//Global packet handler needed for alarm that changes device channel every X second
pcap_t *handle;

void alarm_handler(int sig){
    pcap_breakloop(handle);
}

int main(int argc, char *argv[]) {
    char *device;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    int rst_tables = 0;
    sqlite3 *db;
    char *db_err = 0;
    int rc;

    // Check for the device name argument
    if (argc < 2 || argc > 3) {
        printf("Usage: ./PRO <device in monitor mode> [--new-db]\n");
        return 1;
    }

    // Set the device name
    device = argv[1];
    if(argc > 2){
        if(strcmp(argv[2], "--new-db") == 0){
            rst_tables = 1;
        }
    }
    // Open the device
    handle = pcap_open_live(device, BUFSIZ, 1, 500, errorBuffer);
    if (handle == NULL) {
        printf("Failed to open device %s: %s\n", device, errorBuffer);
        return 1;
    }
    rc = sqlite3_open("pro_db.db", &db);
    if (rc != SQLITE_OK){
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
    if(rst_tables == 0){
        char *create_init_table_sql = "CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, mac_addr TEXT, ssid TEXT, pwr INTEGER, timestamp DATETIME);";
        rc = sqlite3_exec(db, create_init_table_sql, 0, 0, &db_err);

        if(rc != SQLITE_OK){
            fprintf(stderr, "SQL ERR: %s\n", db_err);
            sqlite3_free(db_err);
        }
        else{
            printf("SQLite database connected successfully\n");
        }
    }
    else if(rst_tables == 1){
        char *create_init_table_sql = "DROP TABLE IF EXISTS requests; CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, mac_addr TEXT, ssid TEXT, pwr INTEGER, timestamp DATETIME);";
        rc = sqlite3_exec(db, create_init_table_sql, 0, 0, &db_err);

        if(rc != SQLITE_OK){
            fprintf(stderr, "SQL ERR: %s\n", db_err);
            sqlite3_free(db_err);
        }
        else{
            printf("SQLite database connected successfully\n");
        }
    }
    struct pcap_args args;
    args.db = db;
    // Start capturing packets
    int channel = 1;
    //alarm(1);
    signal(SIGALRM, alarm_handler);
    while(1){
        alarm(HOP_INT);
        pcap_loop(handle, -1, packetHandler, (u_char*)&args);
        //channel = (channel % 4) * 5 + 1;
        //channel = ((channel + 1) % 4) * 5 + 1;
        if (channel == 1){
            channel = 6;
        }
        else if(channel == 6){
            channel = 11;
        }
        else if(channel == 11){
            channel = 1;
        }
        //else if(channel == 14){
        //    channel = 1;
        //}
        else{
            channel = 1;
        }
        char channel_cmd[64];
        sprintf(channel_cmd, "iwconfig %s channel %d", device, channel);
        int cmd_rt = system(channel_cmd);
        if(cmd_rt == -1){
            printf("Failed to run the iwconfig command to change channels. Are you running as root?\n");
            break;
        }
        //printf("Just changed channel to: %d\n", channel);

        //usleep(500 * 1000);
    }
    // Close the handle
    pcap_close(handle);
    sqlite3_close(db);
    return 0;
}


int displayall_callback(void *NotUsed, int num_cols, char **col_vals, char **col_names){
    
    for(int i = 0; i < num_cols; i++){
        printf("\033[1;31m%s:\033[0m %s ", col_names[i], col_vals[i] ? col_vals[i] : "NULL");
        //printf("\033[1;31mClient MAC:\033[0m %s | \033[1;31mSSID:\033[0m %s | \033[1;31mPWR: \033[0m %s", col_vals[0], col_vals[1], col_vals[3]);
    }
    printf("\n");
    return 0;
}


void displayData(const u_char* packet, int count, sqlite3 *db){
    //printf("\033[2J");
    //printf("\033[0;0H");
    //sqlite3 *db = db;
    char *db_err;
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT mac_addr AS MAC, ssid AS SSID, pwr AS PWR, timestamp AS TIMESTAMP FROM requests ORDER BY timestamp DESC LIMIT %d;",DISP_NUM);
    //char sql[] = "SELECT mac_addr AS MAC, ssid AS SSID, pwr AS PWR FROM requests ORDER BY pwr DESC LIMIT 20;";
    //snprintf(sql, sizeof(sql), "INSERT INTO requests (mac_addr, ssid, pwr, timestamp) VALUES ('%02X:%02X:%02X:%02X:%02X:%02X','%s',%hhd,%ld);",packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid, pwr, pkthdr->ts.tv_sec);
    printf("\033[2J");
    printf("\033[0;0H");
    int ret = sqlite3_exec(db, sql, displayall_callback, NULL, &db_err);
    if(ret != SQLITE_OK){
        fprintf(stderr, "Error retrieving record: %s\n", db_err);
        sqlite3_free(db_err);
    }
    /*
    printf("Current packet count: %d\n",count);
    u_char client_mac[] = {packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]};
        //memcpy(client_mac, &packet[28], 6 * sizeof(int));
        //client_mac[7] = '\0';
        //printf("sizeof: %d\n",sizeof(client_mac));
        //printf("debugged: %X\n", client_mac[5]);
        int ssid_length = packet[43];
        if(ssid_length != 0){
            printf("Length of SSID: %d\n",ssid_length);
            char ssid[ssid_length + 1];
            unsigned char pwr = packet[14];
            //signed char pwr_comp = (signed char) pwr;
            for(int i = 0; i < ssid_length + 1; i++){
                ssid[i] = packet[43 + i];
            }
            ssid[ssid_length + 1] = '\0';
            //printf("Reveived probe request for SSID: %s\n", ssid);
            //printf("Received probe request from client with MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]);
            printf("PWR: %hhddB MAC: %02X:%02X:%02X:%02X:%02X:%02X SSID: %s\n",pwr,packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid);
        }
        else{
            printf("Length of SSID: %d\n",ssid_length);
            char ssid[] = "Wildcard *";
            unsigned char pwr = packet[14];
            //signed char pwr_comp = (signed char) pwr;
            //ssid[ssid_length + 1] = '\0';
            //printf("Reveived probe request for SSID: %s\n", ssid);
            //printf("Received probe request from client with MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]);
            printf("PWR: %hhddB MAC: %02X:%02X:%02X:%02X:%02X:%02X SSID: %s\n",pwr,packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid);
        }
        */
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    //struct ieee80211_mgmt *mgmt;
    struct pcap_args* args = (struct pcap_args*)userData;
    sqlite3 *db = args->db;
    char* db_err;
    //char *ssid;
    //char client_mac[7];
    static int count = 0;
    //printf("\033[2J");
    //printf("\033[0;0H");
    //printf("Current packet count: %d\n",++count);
    //printf("Recv packet size: %d\n", pkthdr->len);
    /*
    printf("Payload:\n");
    for(int i =0; i<pkthdr->len; i++){
        if(isprint(packet[i])){
            printf("%c ",packet[i]);
        }
        else{
            printf(" %X ",packet[i]);
        }
        if((i%16==0 && i!=0) || i==pkthdr->len-1){
            printf("\n");
        }
    }
    */
    count++;
    char sql[1024];
    
    if(packet[18] == 0x40) {
        int ssid_length = packet[43];
        if(ssid_length != 0){
            //printf("Length of SSID: %d\n",ssid_length);
            char ssid[ssid_length + 1];
            unsigned char pwr = packet[14];
            signed char pwr_comp = (signed char) pwr;
            for(int i = 0; i < ssid_length; i++){
                ssid[i] = packet[44 + i];
            }
            //ssid[ssid_length + 1] = '\0';
            //unsigned char pwr = packet[14];
            //char* timestamp = pkthdr->ts.tv_sec;
            time_t timestamp_time = pkthdr->ts.tv_sec;
            struct tm* time_info = gmtime(&timestamp_time);
            char datetime[20];
            strftime(datetime, 20, "%Y-%m-%d %H:%M:%S", time_info);

            snprintf(sql, sizeof(sql), "INSERT INTO requests (mac_addr, ssid, pwr, timestamp) VALUES ('%02X:%02X:%02X:%02X:%02X:%02X','%s',%hhd,'%s');",packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid, pwr, datetime);
            //printf("going to run this sql command: %s\n", sql);
            int ret = sqlite3_exec(db, sql, NULL, NULL, &db_err);
            if(ret != SQLITE_OK){
                fprintf(stderr, "Error inserting record: %s\n", db_err);
                sqlite3_free(db_err);
            }
        }
        else{
            char ssid[] = "Wildcard *";
            unsigned char pwr = packet[14];
            time_t timestamp_time = pkthdr->ts.tv_sec;
            struct tm* time_info = gmtime(&timestamp_time);
            char datetime[20];
            strftime(datetime, 20, "%Y-%m-%d %H:%M:%S", time_info);
            snprintf(sql, sizeof(sql), "INSERT INTO requests (mac_addr, ssid, pwr, timestamp) VALUES ('%02X:%02X:%02X:%02X:%02X:%02X','%s',%hhd,'%s');",packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid, pwr, datetime);
            //snprintf(sql, sizeof(sql), "INSERT INTO requests (mac_addr, ssid, pwr, timestamp) VALUES ('%02X:%02X:%02X:%02X:%02X:%02X','%s',%hhd,%ld);",packet[28],packet[29],packet[30],packet[31],packet[32],packet[33], ssid, pwr, pkthdr->ts.tv_sec);
            //printf("going to run this sql command: %s\n", sql);
            int ret = sqlite3_exec(db, sql, NULL, NULL, &db_err);
            if(ret != SQLITE_OK){
                fprintf(stderr, "Error inserting record: %s\n", db_err);
                sqlite3_free(db_err);
            }
        }
        displayData(packet,count,db);
       // printf("We caught a probe request!\n");

    }
    //pcap_breakloop(handle);
}
