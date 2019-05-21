/*
This file is the first include of each cpp file in this library. It defines the symbols common to all translation units. Using this you can use it for precompiled header generation as well. */

#include <cassert>




/** Byte is an unsigned 8-bit number. */
using Byte = unsigned char;

/** You can redefine the ASSERT macro to provide a different implementation of assertion-handling.
For now we're using the default <cassert>'s. */
#define ASSERT assert

/** Custom logging function for warnings. */
#define LOGWARNING printf

/** Custom logging function for regular messages. */
#define LOG printf

/** Custom logging function for debug messages. */
#define LOGD(...)  // ignore

/** Marker for code path that is expectedly unreachable, typically used with a message parameter. */
#define UNREACHABLE LOGD
