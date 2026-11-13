ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif
ifndef KP_DIR
    KP_DIR = ../kp
endif
STAGE ?= 6

CC = $(TARGET_COMPILE)gcc
CFLAGS += -nostdinc -fno-pic -fno-PIC -fno-pie -fno-stack-protector
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions
CFLAGS += -DSTAGE=$(STAGE)

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := alihidden.o

all: Owner_By_ali.kpm
Owner_By_ali.kpm: ${objs}
	${CC} -r -o $@ $^
%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -Talihidden.lds -c -O2 -o $@ $<
clean:
	rm -f *.kpm *.o
