//
//  ViewController.swift
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/14/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var myWebView: UIWebView!
    
    @IBOutlet weak var btnTcpServerTest: UIButton!
    @IBOutlet weak var btnTcpClientTest: UIButton!
    @IBOutlet weak var btnUdpServerTest: UIButton!
    @IBOutlet weak var btnUdpClientTest: UIButton!
    
    @IBOutlet weak var txtPort: UITextField!
    @IBOutlet weak var txtAddr: UITextField!

    @IBAction func TcpServerTestAction(sender: AnyObject) {
        print("TcpServerTestAction\n")
        //let addr_string = txtAddr.text
        //let port:Int32? = Int32(txtPort.text!);
        //cpp_tcp_socket_server_test(addr_string!, port!)
    }
    
    @IBAction func TcpClientTestAction(sender: AnyObject) {
        print("TcpClientTestAction\n")
        //let addr_string = txtAddr.text
        //let port:Int32? = Int32(txtPort.text!);
        //cpp_tcp_socket_client_test(addr_string!, port!)
    }
    
    @IBAction func UdpServerTestAction(sender: AnyObject) {
        print("UdpServerTestAction\n")
        txtAddr.text = "10.242.142.99"
        txtPort.text = "9995"
        //let addr_string = txtAddr.text
        //let port:Int32? = Int32(txtPort.text!);
        //cpp_udp_socket_server_test(addr_string!, port!)
    }
    
    @IBAction func UdpClientTestAction(sender: AnyObject) {
        print("UdpClientTestAction\n")
        //let addr_string = txtAddr.text
        //let port:Int32? = Int32(txtPort.text!);
        //cpp_udp_socket_client_test(addr_string!, port!)
    }
    

    @IBOutlet weak var btnSockTest: UIButton!
    @IBAction func SocksTestAction(sender: AnyObject) {
        // Remove
    }
    
    @IBOutlet weak var WebRequest: UIButton!
    @IBAction func WebRequestAction(sender: AnyObject) {
        // TODO: Re-test
        let url_str = "http://" + txtAddr.text! + "/"
        let url = NSURL (string: url_str);
        //urlTextField.text = url_str;
        let requestObj = NSURLRequest(URL: url!);
        myWebView.loadRequest(requestObj);
    }

    @IBOutlet weak var urlTextField: UITextField!
    
    
    // -------- BEGIN ZEROTIER SERVICE AND PROXY THREAD DEFINITIONS
    
    var service_thread : NSThread!
    func ztnc_start_service() {
        // FIXME: We use this to get a path for the ZeroTierOne service to use, this should be done differently for production
        let path = NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory.DocumentDirectory, NSSearchPathDomainMask.UserDomainMask, true)
        disable_intercept() // We don't want the ZeroTier service to use intercepted calls
        print("\n\nstart_service()\n")
        start_service(path[0])
    }
    
    var proxy: ProxyKitTest! // Object used for testing startup and connectivity of the Proxy Server instance
    var proxy_server_thread : NSThread!
    func ztnc_start_proxy_server() {
        print("\n\nstart_proxy_server()\n")
        proxy = ProxyKitTest()
        proxy.start_proxy_server()
        enable_intercept();
    }
    
    // ------- END
    
    
    override func viewDidLoad() {
        self.view.backgroundColor = UIColor.orangeColor()
        super.viewDidLoad()
        
        txtAddr.text = "10.242.211.245"
        txtPort.text = ""
        
        // ------- BEGIN INITIALIZATION OF ZEROTIER SERVICE AND PROXY
        
        // ZeroTier Service thread
        // This might take 5-10 seconds to start, we have improvements in mind
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
            self.service_thread = NSThread(target:self, selector:"ztnc_start_service", object:nil)
            self.service_thread.start()
        });
        sleep(1)
        // Proxy Server thread
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
            self.proxy_server_thread = NSThread(target:self, selector:"ztnc_start_proxy_server", object:nil)
            self.proxy_server_thread.start()
        });
        
        // ------- END
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

