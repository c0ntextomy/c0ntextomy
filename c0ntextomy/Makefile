BUILD				:= shellcode
TOOLS				:= tools
SRC 				:= src
REC0NTEXTUALIZER	:= $(SRC)/rec0ntextualizer

CC 					:= xcrun clang
CFLAGS 				:=

IOS_CC 				:= xcrun -sdk iphoneos clang
IOS_CFLAGS 			:= -Wl,-e,_start -Wl,-preload -nostdlib -fno-builtin -fno-stack-protector -mno-implicit-float -mno-unaligned-access -I$(REC0NTEXTUALIZER)/payload

VMACHO 				:= $(TOOLS)/vmacho
PYTHON 				:= /usr/bin/env python2.7
BASE64				:= $(PYTHON) -m base64

LLDB_SHELL_TARGET	:= c0ntextomy-lldb-shell
LLDB_SHELL_C		:= $(SRC)/c0ntextomy-lldb-shell.c
MODULES 			:= $(patsubst $(REC0NTEXTUALIZER)/modules/%, $(BUILD)/modules/%.module, $(wildcard $(REC0NTEXTUALIZER)/modules/*))

.PHONY: all clean
all: c0ntextomy-lldb-shell $(BUILD)/payload.arm64.bin $(BUILD)/payload.arm64e.bin $(MODULES)

# uncomment to inspect a faulty shellcode
# .SECONDARY:

$(LLDB_SHELL_TARGET): $(LLDB_SHELL_C)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD)/%.arm64: $(REC0NTEXTUALIZER)/%/*.c | $(BUILD) $(BUILD)/modules
	$(IOS_CC) -arch arm64 $(IOS_CFLAGS) $^ -o $@

$(BUILD)/%.arm64e: $(REC0NTEXTUALIZER)/%/*.c | $(BUILD) $(BUILD)/modules
	$(IOS_CC) -arch arm64e $(IOS_CFLAGS) $^ -o $@

$(BUILD)/%.bin: $(BUILD)/%
	$(VMACHO) -f $^ $@

$(BUILD)/%.b64: $(BUILD)/%.bin
	$(BASE64) $< > $@

$(BUILD)/%.module: $(BUILD)/%.arm64.b64 $(BUILD)/%.arm64e.b64 $(REC0NTEXTUALIZER)/%/module.py
	printf "__payload_arm64__ = '''%s'''\n\n" "`cat $(patsubst %.module, %.arm64.b64, $@)`" > $@
	printf "__payload_arm64e__ = '''%s'''\n\n" "`cat $(patsubst %.module, %.arm64e.b64, $@)`" >> $@
	cat $(patsubst $(BUILD)/%.module, $(REC0NTEXTUALIZER)/%/module.py, $@) >> $@


$(BUILD) $(BUILD)/modules:
	mkdir -p $@

clean:
	rm -rf c0ntextomy-lldb-shell $(BUILD) artifacts
