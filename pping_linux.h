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
#ifndef PPING_LINUX
#define PPING_LINUX

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


static struct in_addr* pping_target = NULL;

void ppCleanup()
{

    free(pping_target);

}

void ppPingAllowed()
{
    if (getuid() != 0) {
        fprintf(stderr, "Pping: root privileges needed.\n");
        exit(1);
    }
}

struct in_addr* ppParseAddress(char* target_string)
{

    pping_target = malloc(sizeof(struct in_addr));
    atexit(&ppCleanup);

    if (inet_aton(target_string, pping_target) == 0)
    {
        fprintf(stderr, "\"%s\" is not a valid IP address\n", target_string);
        exit(1);
    }

    return pping_target;

}

#endif // PPING_LINUX
