/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2015  ZeroTier, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * ZeroTier may be used and distributed under the terms of the GPLv3, which
 * are available at: http://www.gnu.org/licenses/gpl-3.0.html
 *
 * If you would like to embed ZeroTier into a commercial application or
 * redistribute it in a modified binary form, please contact ZeroTier Networks
 * LLC. Start here: http://www.zerotier.com/
 */
#include <jni.h>
#include "jni_utils.h"

#include <dlfcn.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pthread.h>

#include "OneServiceSetup.hpp"
#include "OneService.hpp"
#include "Utils.hpp"
#include "OSUtils.hpp"
#include "Intercept.h"

std::string service_path;
pthread_t intercept_thread;
int * intercept_thread_id;
pthread_key_t thr_id_key;


#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__ANDROID__)
    /*
     * Starts a service thread and performs basic setup tasks
     */
    void init_service(int key, const char * path)
    {
        service_path = path;
        //fprintf(stderr, "init_service(key=%d): tid = %d\n", key, pthread_mach_thread_np(pthread_self()));
        pthread_key_create(&thr_id_key, NULL);
        intercept_thread_id = (int*)malloc(sizeof(int));
        *intercept_thread_id = key;
        pthread_create(&intercept_thread, NULL, startOneService, (void *)(intercept_thread_id));
    }

    /*
     * Enables or disables intercept for current thread using key in thread-local storage
     */
    void set_intercept_status(int mode)
    {
        //fprintf(stderr, "set_intercept_status(mode=%d): tid = %d\n", mode, pthread_mach_thread_np(pthread_self()));
        pthread_key_create(&thr_id_key, NULL);
        intercept_thread_id = (int*)malloc(sizeof(int));
        *intercept_thread_id = mode;
        pthread_setspecific(thr_id_key, intercept_thread_id);
        //set_thr_key(thr_id_key);
        set_up_intercept();
    }
#endif

/*
 * Starts a new service instance
 */
#if defined(__ANDROID__)
    JNIEXPORT void JNICALL Java_Netcon_NetconWrapper_startOneService(JNIEnv *env, jobject thisObj)
#else
    void *start_OneService(void *thread_id)
#endif
    {

        LOGV("startOneService(): In service call code\n");
        chdir(service_path.c_str());
        //fprintf(stderr, "\nSERVICE PATH (tid=%d): %s\n", pthread_mach_thread_np(pthread_self()), service_path.c_str());
        static ZeroTier::OneService *volatile zt1Service = (ZeroTier::OneService *)0;
        static std::string homeDir = "";
      
#if defined(__APPLE__)
#include "TargetConditionals.h"
#if TARGET_IPHONE_SIMULATOR
        // homeDir = "dont/run/this/in/the/simulator";
#elif TARGET_OS_IPHONE
        homeDir = "ZeroTier/One";
#endif
#endif
        // homeDir = OneService::platformDefaultHomePath();
        if (!homeDir.length()) {
            return;
        } else {
            std::vector<std::string> hpsp(ZeroTier::Utils::split(homeDir.c_str(),ZT_PATH_SEPARATOR_S,"",""));
            std::string ptmp;
            if (homeDir[0] == ZT_PATH_SEPARATOR)
                ptmp.push_back(ZT_PATH_SEPARATOR);
            for(std::vector<std::string>::iterator pi(hpsp.begin());pi!=hpsp.end();++pi) {
                if (ptmp.length() > 0)
                    ptmp.push_back(ZT_PATH_SEPARATOR);
                ptmp.append(*pi);
                if ((*pi != ".")&&(*pi != "..")) {
                    if (!ZeroTier::OSUtils::mkdir(ptmp))
                        throw std::runtime_error("home path does not exist, and could not create");
                }
            }
        }

        // Add network config file
        std::string ios_default_nwid = "e5cd7a9e1c3511dd";
        std::string netDir = homeDir + "/networks.d";
        std::string confFile = netDir + "/" + ios_default_nwid + ".conf";
        if(!ZeroTier::OSUtils::mkdir(netDir)) {
            LOGV("unable to create %s\n", netDir.c_str());
        }
        if(!ZeroTier::OSUtils::writeFile(confFile.c_str(), "")) {
            LOGV("unable to write network conf file: %s\n", ios_default_nwid.c_str());
        }
        

        LOGV("homeDir = %s", homeDir.c_str());
        for(;;) {
            zt1Service = ZeroTier::OneService::newInstance(homeDir.c_str(),9991);
            switch(zt1Service->run()) {
                case ZeroTier::OneService::ONE_STILL_RUNNING: // shouldn't happen, run() won't return until done
                case ZeroTier::OneService::ONE_NORMAL_TERMINATION:
                    break;
                case ZeroTier::OneService::ONE_UNRECOVERABLE_ERROR:
                    //fprintf(stderr,"%s: fatal error: %s" ZT_EOL_S,argv[0],zt1Service->fatalErrorMessage().c_str());
                    //returnValue = 1;
                    break;
                case ZeroTier::OneService::ONE_IDENTITY_COLLISION: {
                    delete zt1Service;
                    zt1Service = (ZeroTier::OneService *)0;
                    std::string oldid;
                    //OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str(),oldid);
                    if (oldid.length()) {
                        //OSUtils::writeFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret.saved_after_collision").c_str(),oldid);
                        //OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str());
                        //OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.public").c_str());
                    }
                }   continue; // restart!
            }
            break; // terminate loop -- normally we don't keep restarting
        }
        return;
    }

#ifdef __cplusplus
}
#endif
