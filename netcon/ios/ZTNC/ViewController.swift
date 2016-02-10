//
//  ViewController.swift
//  ZTNC
//
//  Created by Joseph Henry on 2/2/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

import UIKit
import CFNetwork

class ViewController: UIViewController {
    
    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var getButton: UIButton!
    @IBOutlet weak var myWebView: UIWebView!
    
    @IBAction func getButtonAction(sender: AnyObject) {
        //let url_str = "http://10.242.9.160:8083/"
        //let url = NSURL (string: url_str);
        //urlTextField.text = url_str;
        //let requestObj = NSURLRequest(URL: url!);
        //myWebView.loadRequest(requestObj);
        
        //CFSocketRef CFSocketCreate(CFAllocatorRef allocator, SInt32 protocolFamily, SInt32 socketType, SInt32 protocol, CFOptionFlags callBackTypes, CFSocketCallBack callout, const CFSocketContext *context)
        //let sock = CFSocketCreate(nil, AF_INET, SOCK_STREAM, 0, 0, nil, nil)
        //print("sock = %d\n", sock)
        
        //static CFSocketRef _CFSocketCreateWithNative(CFAllocatorRef allocator, CFSocketNativeHandle sock, CFOptionFlags callBackTypes, CFSocketCallBack callout, const CFSocketContext *context, Boolean useExistingInstance)
        //let native_sock = socket(AF_INET, SOCK_STREAM, 0)
        //let cfsock = CFSocketCreateWithNative(nil, native_sock, 0, nil, nil)
        //print("native_sock = %d\n", native_sock)

        // Below is code which calls a wrapped C++ test that uses an intercepted socket API
        // Note, intercepting of CF methods is currently not supported
        urlTextField.text = ""
        let addr_string = "10.242.9.160"
        let port : Int32 = 1000
        urlTextField.text = String.fromCString(cpp_intercepted_socket_api_test(addr_string, port))

    }
    
    func ztnc_start_service() {
        print("Starting service\n")
        start_service()
    }
    func ztnc_start_intercept() {
        print("Starting intercept\n")
        start_intercept()
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let service_thread = NSThread(target:self, selector:"ztnc_start_service", object:nil)
        service_thread.start()
        sleep(5)
        ztnc_start_intercept()
        
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

