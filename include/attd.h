//
// Created by FANGG3 on 25-7-22.
//

#ifndef ATTD_ATTD_H
#define ATTD_ATTD_H
#include "stdarg.h"
extern "C" {
__attribute__((visibility ("default"))) void attd(void *target_addr);
__attribute__((visibility ("default"))) void attd_trace(void *addr);
__attribute__((visibility ("default"))) void attd_call(void *target_addr,int argNum,...);
}
#endif //ATTD_ATTD_H
