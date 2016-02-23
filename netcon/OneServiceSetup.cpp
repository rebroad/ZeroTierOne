//
//  Mock.cpp
//  ZTNC
//
//  Created by Joseph Henry on 2/1/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#include "lwip/init.h"
#include "lwip/tcp_impl.h"
#include "netif/etharp.h"
#include "lwip/api.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/ip_frag.h"
#include "lwip/tcp.h"

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

#define IOS_SERVICE_THREAD_ID   222

/*
 * Starts a service thread and performs basic setup tasks
 */
void init_service(int key, const char * path)
{
    service_path = path;
    fprintf(stderr, "init_service(key=%d): tid = %d\n", key, pthread_mach_thread_np(pthread_self()));
    pthread_key_create(&thr_id_key, NULL);
    intercept_thread_id = (int*)malloc(sizeof(int));
    *intercept_thread_id = key;
    pthread_create(&intercept_thread, NULL, start_OneService, (void *)(intercept_thread_id));
}

/*
 * Loads symbols for intercept and performs basic setup tasks
 */
void init_intercept(int key)
{
    fprintf(stderr, "init_intercept(key=%d): tid = %d\n", key, pthread_mach_thread_np(pthread_self()));
    pthread_key_create(&thr_id_key, NULL);
    intercept_thread_id = (int*)malloc(sizeof(int));
    *intercept_thread_id = key;
    set_up_intercept();
    pthread_setspecific(thr_id_key, intercept_thread_id);
    set_thr_key(thr_id_key);
}

/*
 * Starts a new service instance
 */
void *start_OneService(void *thread_id)
    {
        chdir(service_path.c_str());
        fprintf(stderr, "\nSERVICE PATH (tid=%d): %s\n", pthread_mach_thread_np(pthread_self()), service_path.c_str());
        static ZeroTier::OneService *volatile zt1Service = (ZeroTier::OneService *)0;
        static std::string homeDir = "";
        // /Users/Joseph/Library/Developer/CoreSimulator/Devices/0380D5D4-BD2E-4D3D-8930-2E5C3F25C3E1/data/Library/Application Support/ZeroTier/One
        if (!homeDir.length())
            // FIXME: Symlinked to /iosdev since the true directory is too long to fit in a sun_path, in production this should be removed
            
#if defined(__APPLE__)
#include "TargetConditionals.h"
#if TARGET_IPHONE_SIMULATOR
            //setpath("/iosdev/data/Library/Application Support/ZeroTier/One/nc_e5cd7a9e1c87bace"); // for intercept
            homeDir = "/iosdev/data/Library/Application Support/ZeroTier/One";
#elif TARGET_OS_IPHONE
        homeDir = "ZeroTier/One";
        //setpath("ZeroTier/One/nc_e5cd7a9e1c87bace");
#endif
#endif
        
            // homeDir = OneService::platformDefaultHomePath();
        if (!homeDir.length()) {
            //fprintf(stderr,"%s: no home path specified and no platform default available" ZT_EOL_S,argv[0]);
            return NULL;
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
        std::string ios_default_nwid = "e5cd7a9e1c87bace";
        std::string netDir = homeDir + "/networks.d";
        std::string confFile = netDir + "/" + ios_default_nwid + ".conf";
        if(!ZeroTier::OSUtils::mkdir(netDir)) {
            printf("unable to create %s\n", netDir.c_str());
        }
        if(!ZeroTier::OSUtils::writeFile(confFile.c_str(), "")) {
            printf("unable to write network conf file: %s\n", ios_default_nwid.c_str());
        }
        
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
                }	continue; // restart!
            }
            break; // terminate loop -- normally we don't keep restarting
        }
        return NULL;
    }
