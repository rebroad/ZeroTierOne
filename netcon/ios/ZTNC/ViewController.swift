//
//  ViewController.swift
//  ZTNC
//
//  Created by Joseph Henry on 2/2/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

import NewFramework

import UIKit
import CFNetwork


class ViewController: UIViewController {
    
    @IBAction func actionRestartService(sender: AnyObject) {
        // TODO: A mechanism for detecting this "cancel" should be build into the thread. Is this possible for a C++ static lib?
        //service_thread.cancel();
        //service_thread = NSThread(target:self, selector:"ztnc_start_service", object:nil)
        //service_thread.start()
    }
    
    @IBOutlet weak var btnRestartService: UIButton!
    @IBOutlet weak var urlTextField: UITextField!
    @IBOutlet weak var getButton: UIButton!
    @IBOutlet weak var myWebView: UIWebView!
    @IBOutlet weak var myTextView: UITextView!
    
    /*
    var debug_thread : NSThread!
    var service_thread : NSThread!
    var intercept_thread : NSThread!
    */
    
    @IBAction func getButtonAction(sender: AnyObject) {
        
        // All of the below examples demonstrate how to use intercepted socket calls:
        // Instructions: None
        
        let url_str = "http://10.242.9.160:8083/"
        let url = NSURL (string: url_str);
        urlTextField.text = url_str;
        let requestObj = NSURLRequest(URL: url!);
        myWebView.loadRequest(requestObj);
        
        // Creating a CFSocket
        /*
        let sock = CFSocketCreate(nil, AF_INET, SOCK_STREAM, 0, 0, nil, nil)
        print("sock = %d\n", sock)
        */
        
        /*
        // Creating a native socket and wrapping it using the CFSocket API
        let native_sock = socket(AF_INET, SOCK_STREAM, 0)
        let cfsock = CFSocketCreateWithNative(nil, native_sock, 0, nil, nil)
        print("native_sock = %d\n", native_sock)
        */
        
        /*
        // Simple Echo server test using classic socket API
        urlTextField.text = ""
        let addr_string = "10.242.9.160"
        let port : Int32 = 1000
        urlTextField.text = String.fromCString(cpp_intercepted_socket_api_test(addr_string, port))
        */
    }
    
    func ztnc_start_service() {
        // FIXME: We use this to get a path for the ZeroTierOne service to use, this should be done differently for production
        let path = NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory.DocumentDirectory, NSSearchPathDomainMask.UserDomainMask, true)
        print("Starting service\n")
        start_service(path[0])
    }
    func ztnc_start_intercept() {
        print("Starting intercept\n")
        start_intercept()
    }
    /*
    func debug_watcher() {
        while(true) {
            
            var debug_str : String = ""
            
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
                    debug_str = String.fromCString(get_debug_msg_from_ztnc()) ?? "";
                
                if (debug_str.characters.count > 0) {
                    dispatch_async(dispatch_get_main_queue(), {
                        self.myTextView.text.appendContentsOf(debug_str + "\n")
                        let range = NSMakeRange(self.myTextView.text.characters.count - 1, 0)
                        self.myTextView.scrollRangeToVisible(range)
                    });
                    debug_str = ""
                }
            });
            usleep(10000)
        }
    }
    */
    override func viewDidLoad() {
        super.viewDidLoad()
        
        myTextView.backgroundColor = UIColor.blackColor()
        myTextView.textColor = UIColor.greenColor()
        myTextView.font = UIFont(name: "Courier New", size: 12);
        myTextView.text = ""
        
        // Logging re-direction thread (super-primitive on-device debug output)
        /*
        debug_thread = NSThread(target:self, selector:"debug_watcher", object:nil)
        debug_thread.start()
        */
        
        // Service thread
        /*
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
            self.service_thread = NSThread(target:self, selector:"ztnc_start_service", object:nil)
            self.service_thread.start()
        });

        sleep(2)
        */
        //ztnc_start_intercept()
        fish_test_rebind()
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

