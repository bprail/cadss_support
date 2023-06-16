cadss.cpp builds a simple pin tool to generate traces

Currently, it builds in source/tools/SimpleExamples with pin by modifying the
makefile.rules to include cadss as a tool.

It runs without specific arguments, for example:
pin -t source/tools/SimpleExamples/obj-intel64/cadss.so -- /bin/ls
