#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pwnio.h"

#define PADSIZE         0x4
const char title[] = "  ============================================================================\n"
                     "// _|_|_|_|_|  _|_|_|  _|      _|  _|      _|  _|_|_|      _|_|    _|_|_|     \\\\\n"
                     "||     _|        _|    _|_|    _|    _|  _|    _|    _|  _|    _|  _|    _|   ||\n"
                     "||     _|        _|    _|  _|  _|      _|      _|_|_|    _|_|_|_|  _|    _|   ||\n"
                     "||     _|        _|    _|    _|_|      _|      _|        _|    _|  _|    _|   ||\n"
                     "\\\\     _|      _|_|_|  _|      _|      _|      _|        _|    _|  _|_|_|     //\n"
                     "  ============================================================================\n";
const char separator[] = "+------------------------------------------------------------------------------+\n";
const char menu[] = "+- MENU -----------------------------------------------------------------------+\n"
                    "| [A] Add memo                                                                 |\n"
                    "| [D] Delete memo                                                              |\n"
                    "| [E] Edit memo                                                                |\n"
                    "| [Q] Quit                                                                     |\n"
                    "+------------------------------------------------------------------------------+\n";

const char show_index[] = " #   INDEX: ";
const char show_content[] = " # CONTENT: ";
const char confirm_content[] = "CONTENT: ";

const char prompt_cmd[] = "(CMD)>>> ";
const char prompt_size[] = "(SIZE)>>> ";
const char prompt_content[] = "(CONTENT)>>> ";
const char prompt_index[] = "(INDEX)>>> ";
const char prompt_confirm[] = "(Y/n)>>> ";

const char errmsg_no_space_left[] = "No space is left.";
const char errmsg_no_such_command[] = "No such a command";
const char errmsg_invalid_index[] = "Invalid index";
const char errmsg_not_used[] = "Not used";

const char syserr_no_memory_is_available[] = "[!] No memory is available.";
const char syserr_init_failed[] = "[!] Init failed.";
const char msg_confirm[] = "Is it OK?";
const char msg_timeout[] = "Timeout.";

const size_t memo_maxlen = 0x100;
struct {
    char buffer[0x100]; // make a fakechunk.
    struct {
        size_t size;
        char *memo;
    } page[4];
} tinypad;

static inline void dummyinput(int c)
{
    if(!c) return;
    char dummy = '\0';
    while(dummy != c) 
        read_n(&dummy, 1);
}


int getcmd()
{
    int cmd = '\0';

    write_n(menu, strlen(menu));

    write_n(prompt_cmd, strlen(prompt_cmd)); 
    read_until((char *)&cmd, 1, '\n');
    write_n("\n", 1);

    return toupper(cmd);
}

int main()
{
    int cmd = '\0';

    write_n("\n", 1);
    write_n(title, strlen(title));
    write_n("\n", 1);
    do{
        for(int i = 0; i < PADSIZE; i++) {
            char count = '1'+i;
            writeln(separator, strlen(separator));

            write_n(show_index, strlen(show_index)); writeln(&count, 1);
            write_n(show_content, strlen(show_content));
            if(tinypad.page[i].memo) {
                writeln(tinypad.page[i].memo, strlen(tinypad.page[i].memo));
            }
            writeln("\n", 1);
        }
        int idx = 0;
        switch(cmd = getcmd()) {
            case 'A': {
                    while(idx < PADSIZE && tinypad.page[idx].size != 0) idx++;
                    if(idx == PADSIZE) {
                        writeln(errmsg_no_space_left, strlen(errmsg_no_space_left));
                        break;
                    }
                    int size = -1;
                    write_n(prompt_size, strlen(prompt_size)); 
                    size = read_int();
                    size =  (size <    0x1)? 0x1:
                            (size <  memo_maxlen)? size: memo_maxlen;
                    tinypad.page[idx].size = size;

                    if((tinypad.page[idx].memo = malloc(size)) == NULL) {
                        writerrln("[!] No memory is available.", strlen("[!] No memory is available."));
                        _exit(-1);
                    }

                    write_n(prompt_content, strlen(prompt_content));
                    read_until(tinypad.page[idx].memo, size, '\n');
                    writeln("\nAdded.", strlen("\nAdded."));
                } break;
            case 'D': {
                    write_n(prompt_index, strlen(prompt_index));
                    idx = read_int();
                    if(!(0 < idx && idx <= PADSIZE)) {
                        writeln(errmsg_invalid_index, strlen(errmsg_invalid_index));
                        break;
                    }
                    if(tinypad.page[idx-1].size == 0) {
                        writeln(errmsg_not_used, strlen(errmsg_not_used));
                        break;
                    }

                    // XXX: UAF
                    free(tinypad.page[idx-1].memo);
                    tinypad.page[idx-1].size = 0;

                    writeln("\nDeleted.", strlen("\nDeleted."));
                } break;
            case 'E': {
                    write_n(prompt_index, strlen(prompt_index));
                    idx = read_int();
                    if(!(0 < idx && idx <= PADSIZE)) {
                        writeln(errmsg_invalid_index, strlen(errmsg_invalid_index));
                        break;
                    }
                    if(tinypad.page[idx-1].size == 0) {
                        writeln(errmsg_not_used, strlen(errmsg_not_used));
                        break;
                    }

                    int confirmation = '0';
                    strcpy(tinypad.buffer, tinypad.page[idx-1].memo);
                    while(toupper(confirmation) != 'Y') {
                        write_n(confirm_content, strlen(confirm_content));
                        writeln(tinypad.buffer, strlen(tinypad.buffer));
                        write_n(prompt_content, strlen(prompt_content));
                        // XXX: Not NUL Terminated.
                        read_until(tinypad.buffer, strlen(tinypad.page[idx-1].memo), '\n');
                        writeln(msg_confirm, strlen(msg_confirm));
                        write_n(prompt_confirm, strlen(prompt_confirm));
                        read_until((char *)&confirmation, 1, '\n');
                    }
                    strcpy(tinypad.page[idx-1].memo, tinypad.buffer);

                    writeln("\nEdited.", strlen("\nEdited."));
                } break;
            default:
                writeln(errmsg_no_such_command, strlen(errmsg_no_such_command));
            case 'Q':
                break;
        }
    } while(cmd != 'Q');

    return 0;
}
