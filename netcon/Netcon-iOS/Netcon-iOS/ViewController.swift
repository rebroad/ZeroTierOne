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
        
        test_intercepted_proxy_streams()
        
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
    
    
    
    
    /*
    Test HTTP GET request using Intercepted-Proxified NSStreams Serviced by Network Containers, damn that's a mouthful
    
    To summarize what's happening:
    
                    (-2) Start ZeroTierOne service thread
                    (-1) Start SOCKS Proxy service thread
    YOU ARE HERE --> (0) Create your streams
                     (1) Create your SOCKS Proxy config dictionary
                     (2) Pass config dictionary to streams
                     (3) Use your streams
    
    For this early integration we are using port 1337 as a sort of "magic port" that will allow the intercept
    code to filter socket API calls. For instance, when we intercept the SOCKS proxy we only want to intercept
    the calls outbound to the network and not the calls to connect to the proxy service itself.
    */
    func test_intercepted_proxy_streams()
    {
        // For HTTP request
        var buffer = [UInt8](count: 100, repeatedValue: 0)
        let str = "GET / HTTP/1.0\r\n\r\n"
        //let str = "Welcome to the machine"
        print("strlen = %d\n", str.characters.count)
        let encodedDataArray = [UInt8](str.utf8)
        
        var inputStream:NSInputStream?
        var outputStream:NSOutputStream?
        
        // As usual, get our streams to our desired "local" address
        NSStream.getStreamsToHostWithName("10.5.5.2", port: Int(80), inputStream: &inputStream, outputStream: &outputStream)
        
        // SOCKS Proxy config dictionary
        let myDict:NSDictionary = [NSStreamSOCKSProxyHostKey : "0.0.0.0",
            NSStreamSOCKSProxyPortKey : 1337,
            NSStreamSOCKSProxyVersionKey : NSStreamSOCKSProxyVersion5]
        
        // Give configuration to NSStreams
        inputStream!.setProperty(myDict, forKey: NSStreamSOCKSProxyConfigurationKey)
        outputStream!.setProperty(myDict, forKey: NSStreamSOCKSProxyConfigurationKey)
        
        /* If you're interested in what happens next:
        
        NSStream objects will generate native sockets internally which then connect to
        the SOCKS proxy on 'localhost'. Once this connection is established the Proxy server
        will handle a connection request to the "local address" of your choice. The subsequent
        socket(), and connect() calls will be intercepted and sent to the Netcon service via
        an RPC mechanism mediated by unix domain sockets. These RPC calls are dissected and
        sent to the lwIP stack and finally to the ZeroTierOne service
        */
        
        inputStream!.open()
        outputStream!.open()
        
        sleep(1)
        outputStream?.write(encodedDataArray, maxLength: encodedDataArray.count)
        //sleep(5)
        //inputStream?.read(&buffer, maxLength: 100)
        //print("buffer = \(buffer)\n")
    }
    
    
    
    
    // -------- BEGIN ZEROTIER SERVICE AND PROXY THREAD DEFINITIONS
    
    var service_thread : NSThread!
    func ztnc_start_service() {
        // FIXME: We use this to get a path for the ZeroTierOne service to use, this should be done differently for production
        let path = NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory.DocumentDirectory, NSSearchPathDomainMask.UserDomainMask, true)
        //disable_intercept() // We don't want the ZeroTier service to use intercepted calls
        print("start_service()\n")
        start_service(path[0])
    }
    
    //var proxy: ProxyKitTest! // Object used for testing startup and connectivity of the Proxy Server instance
    var proxy_server_thread : NSThread!
    func ztnc_start_proxy_server() {
        //print("\n\nstart_proxy_server()\n")
        // proxy = ProxyKitTest()
        // proxy.start_proxy_server()
        //enable_intercept();
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
        /*
        sleep(1)
        // Proxy Server thread
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), {
            self.proxy_server_thread = NSThread(target:self, selector:"ztnc_start_proxy_server", object:nil)
            self.proxy_server_thread.start()
        });
        */
        // ------- END
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

