#include "frida-gum.h"
#include "hookUtils.h"
#include "logger.h"
#include "vm.h"
#include <cstdint>
#include <cstring>
#include <jni.h>
#include <sstream>
#include <string>
#include <thread>

static std::string m_so_path;

void syn_reg_gum(GumCpuContext *cpu, QBDI::GPRState *state, bool F2Q) {

  if (F2Q) {
    for (int i = 0; i < 29; i++) {
      QBDI_GPR_SET(state, i, cpu->x[i]);
    }
    state->lr = cpu->lr;
    state->sp = cpu->sp;
    state->x29 = cpu->fp;
    state->nzcv = cpu->nzcv;

  } else {
    for (int i = 0; i < 29; i++) {
      cpu->x[i] = QBDI_GPR_GET(state, i);
    }
    cpu->fp = state->x29;
    cpu->lr = state->lr;
    cpu->sp = state->sp;
    cpu->nzcv = state->nzcv;
  }
}

bool isTraceAll = false;

// hook
HOOK_DEF(QBDI::rword, gum_handle) {
  LOGS("begin");
  clock_t start, end;
  start = clock();
  auto context = gum_interceptor_get_current_invocation();
  auto interceptor =
      (GumInterceptor *)gum_invocation_context_get_replacement_data(context);
  gum_interceptor_revert(interceptor, context->function);
  gum_interceptor_flush(interceptor);
  auto vm_ = new vm();
  auto qvm = vm_->init(context->function, isTraceAll);
  auto state = qvm.getGPRState();
  syn_reg_gum(context->cpu_context, state, true);
  uint8_t *fakestack;
  QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
  QBDI::rword ret;
  qvm.switchStackAndCall(&ret, (QBDI::rword)context->function);
  syn_reg_gum(context->cpu_context, state, false);
  end = clock();
  LOGS("time: %f", (double)(end - start) / CLOCKS_PER_SEC);
  LOGS("end");
  return ret;
}

// export
extern "C" void _init(void) { gum_init_embedded(); }
extern "C" {
__attribute__((visibility("default"))) void attd(void *target_addr) {
  LOGD("hooking %p", target_addr);
  hookUtils::gum_replace(target_addr, (void *)new_gum_handle,
                         (void **)(&orig_gum_handle));
}

__attribute__((visibility("default"))) void attd_trace(void *addr,
                                                       bool trace_all) {
  isTraceAll = trace_all;
  attd(addr);
}
void attd_call(void *target_addr, int argNum, ...) {
  LOGS("attd_call start %p", target_addr);
  uint8_t *fakestack;
  auto vm_ = new vm();
  auto qvm = vm_->init(target_addr);
  auto state = qvm.getGPRState();
  QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
  QBDI::rword ret;
  va_list args;
  va_start(args, argNum);
  va_list ap;
  qvm.callV(&ret, (QBDI::rword)target_addr, argNum, ap);
  va_end(args);

  LOGS("attd_call end %p", target_addr);
}
}

static struct AttdConfig {
  char* target_so;
  uintptr_t address;
  int hook_delay;
} _config;

void *sub_thread(AttdConfig *config) {

  // std::this_thread::sleep_for(std::chrono::seconds(_config.hook_delay));

  LOGD("config: %s %lx %d", config->target_so, config->address,
       config->hook_delay);
  sleep(config->hook_delay);

  auto base = getSoBaseAddress(config->target_so).start;
  LOGD("%s base: %lx", config->target_so, base);
  if (base != 0) {
    attd((void *)(base + config->address));
  }
  return nullptr;
}

__unused __attribute__((constructor)) void init_main() {
  LOGD("load attd ok !!");
  Dl_info info;
  dladdr((void *)init_main, &info);
  m_so_path = info.dli_fname;

  if (m_so_path.empty()) {
    LOGD("m_so_path is empty");
  } else {
    LOGD("m_so_path: %s", m_so_path.c_str());
    auto config_path = m_so_path + ".config";
    if (access(config_path.c_str(), F_OK) == 0) {
      FILE *f = fopen64(config_path.c_str(), "r");
      if (f) {
        char buf[1024];
        fread(buf, 1, 1024, f);
        fclose(f);
        LOGD("config: %s", buf);
        //.config 文件内容 为 target_so|address|hook_delay 实例化 _config

        std::string line(buf);
        std::stringstream ss(line);
        std::string token;
        std::getline(ss, token, '|');
        if (token.empty()) {
          LOGE("config file format error");
          return;
        }

        _config.target_so = strdup(token.c_str());
        std::getline(ss, token, '|');
        if (token.empty()) {
          LOGE("config file format error");
          return;
        }
        _config.address = std::stoull(token, nullptr, 16);
        std::getline(ss, token, '|');
        if (token.empty()) {
          LOGE("config file format error");
          return;
        }
        _config.hook_delay = std::stoi(token);
        std::thread t(sub_thread, &_config);
        t.detach();

      } else {
        LOGD("config file open failed");
      }

    } else {
      LOGD("config file not exist");
    }
  }
}