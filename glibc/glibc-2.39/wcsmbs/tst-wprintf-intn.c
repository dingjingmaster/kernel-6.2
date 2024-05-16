/* Test printf formats for intN_t, int_leastN_t and int_fastN_t types.
   Wide string version.
   Copyright (C) 2023-2024 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#define SNPRINTF swprintf
#define TEST_COMPARE_STRING_MACRO TEST_COMPARE_STRING_WIDE
#define STRLEN wcslen
#define CHAR wchar_t
#define L_(C) L ## C

#include "../stdio-common/tst-printf-intn-main.c"
