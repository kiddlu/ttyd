CPUS=$(shell cat /proc/cpuinfo | grep "processor" | wc -l)
PWD=$(shell pwd)
BUILD_DIR=$(PWD)/build
MAKE_OPT=

define shcmd-makepre
	@echo "[shcmd-makepre]"
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ..
endef

define shcmd-make
	@echo "[shcmd-make]"
	@cd $(BUILD_DIR) && make -j$(CPUS) $(MAKE_OPT) | grep -v "^make\[[0-9]\]:"
endef

define shcmd-makeclean
	@echo "[shcmd-makeclean]"
	@if [ -d $(BUILD_DIR) ]; then (cd $(BUILD_DIR) && make clean && echo "##Clean build##"); fi
endef

define shcmd-makerm
	@echo "[shcmd-makerm]"
	@if [ -d $(BUILD_DIR) ]; then (rm -rf $(BUILD_DIR)); fi
endef

define shcmd-pre-make-custom
	@echo "[shcmd-pre-make-custom]"
	@echo Codelines Sum:
	@find src | grep -E "\.c|\.h" | xargs cat | wc -l
	@find src | grep -E "\.c|\.h" | xargs clang-format-19 -i
endef

define shcmd-post-make-custom
	@echo "[shcmd-post-make-custom]"
endef

.PHONY: all clean rm pre
all: pre
	$(call shcmd-pre-make-custom)
	$(call shcmd-make)
	$(call shcmd-post-make-custom)

clean:
	$(call shcmd-makeclean)

rm:
	$(call shcmd-makerm)

pre:
	$(call shcmd-makepre)
