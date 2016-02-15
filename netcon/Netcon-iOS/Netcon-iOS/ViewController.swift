//
//  ViewController.swift
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/14/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var getButton: UIButton!
    @IBOutlet weak var myWebView: UIWebView!
    
    @IBAction func getButtonAction(sender: AnyObject) {
        // Simple Echo server test using classic socket API
        let addr_string = "10.242.9.160"
        let port : Int32 = 1000
        cpp_intercepted_socket_api_test(addr_string, port)
        
        /*
        let url_str = "http://10.242.9.160:8083/"
        let url = NSURL (string: url_str);
        //urlTextField.text = url_str;
        let requestObj = NSURLRequest(URL: url!);
        myWebView.loadRequest(requestObj);
        // Do any additional setup after loading the view, typically from a nib.
        */
    }
    var service_thread : NSThread!
    @IBOutlet weak var urlTextField: UITextField!
    
    func ztnc_start_service() {
        // FIXME: We use this to get a path for the ZeroTierOne service to use, this should be done differently for production
        let path = NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory.DocumentDirectory, NSSearchPathDomainMask.UserDomainMask, true)
        print("Starting service\n")
        start_service(path[0])
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Service thread
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
        self.service_thread = NSThread(target:self, selector:"ztnc_start_service", object:nil)
        self.service_thread.start()
        });
        
        start_intercept()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

