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
        let addr_string = txtAddr.text
        let port:Int32? = Int32(txtPort.text!);
        cpp_tcp_socket_server_test(addr_string!, port!)
    }
    
    @IBAction func TcpClientTestAction(sender: AnyObject) {
        print("TcpClientTestAction\n")
        let addr_string = txtAddr.text
        let port:Int32? = Int32(txtPort.text!);
        cpp_tcp_socket_client_test(addr_string!, port!)
    }
    
    @IBAction func UdpServerTestAction(sender: AnyObject) {
        print("UdpServerTestAction\n")
        txtAddr.text = "10.242.142.99"
        txtPort.text = "9995"
        let addr_string = txtAddr.text
        let port:Int32? = Int32(txtPort.text!);
        cpp_udp_socket_server_test(addr_string!, port!)
    }
    
    @IBAction func UdpClientTestAction(sender: AnyObject) {
        print("UdpClientTestAction\n")
        let addr_string = txtAddr.text
        let port:Int32? = Int32(txtPort.text!);
        cpp_udp_socket_client_test(addr_string!, port!)
    }

    @IBOutlet weak var WebRequest: UIButton!
    @IBAction func WebRequestAction(sender: AnyObject) {
        let url_str = "http://" + txtAddr.text! + "/"
        let url = NSURL (string: url_str);
        //urlTextField.text = url_str;
        let requestObj = NSURLRequest(URL: url!);
        myWebView.loadRequest(requestObj);
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
        self.view.backgroundColor = UIColor.orangeColor()
        //txtAddr.keyboardType = UIKeyboardType.NumberPad
        //txtPort.keyboardType = UIKeyboardType.NumberPad
        super.viewDidLoad()
        
        txtAddr.text = "10.242.211.245"
        txtPort.text = ""
        
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

