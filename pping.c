/*
 * MIT License
 *
 * PPING Copyright (c) 2014-2016 Sebastien Serre <ssbx@sysmo.io>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <cargo.h>


#ifdef linux
#include "pping_linux.h"
#elif  _WIN32
#include "pping_win32.h"
#endif // LINUX

int main(int argc, char* argv[])
{

    char* target_string = cargoFlag("host", "", argc, argv);
    char* icmp_version  = cargoFlag("version", "4", argc, argv);

    struct in_addr *target = parse_address(target_string);

    if (strcmp(icmp_version, "4") == 0) {
        printf("IPV4 mode\n");
    } else if (strcmp(icmp_version, "6") == 0) {
        printf("IPV6 mode\n");
    }

    return 0;

}
