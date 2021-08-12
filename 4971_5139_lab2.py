import sys
import os
import enum
import re
import socket


class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        (just join the already existing fields by \r\n)
        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        method = self.method
        path = self.requested_path
        version = "HTTP/1.0\r\n"
        http_string = method+' ' + path+' ' + version
        for header in self.headers:
            http_string += header[0] + ':' + ' ' + header[1] + '\r\n'
        http_string += '\r\n'
        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """


        object = self.message + ' ' + self.code

        print("error type",object)
        return object

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())



class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.
    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None


def setup_sockets(proxy_port_number):
    print("HTTP proxy !!!!!!!!!!!!!!!!!!!!")
    print("Starting HTTP proxy on port:", proxy_port_number)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', int(proxy_port_number)))

    s.listen(15)

    client, address = s.accept()
    print("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
    space = ""
    emt = ""
    while 1:
        string = client.recv(11000)
        print("recieved data", string)
        if string == b'\r\n':
            emt = space
            break
        else:
            space += string.decode('utf-8')
    pt = str(space.split("\r\n"))
    print("ur request is :", string)
    u = pt.split()[1][0:3]
    print("ur proxy is fine !!!")
    e = str(space.split("\r\n"))
    l = e.split()[1][0:6]
    if u != "www" and l != "http:/":
        space += "\r\n"
    print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
    command = http_request_pipeline(("127.0.0.1", 9877), space)
    print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
    s.connect(command.requested_host, command.requested_port)
    print("hosttt", command.requested_host)
    s.sendall((command.method + " " + command.requested_path + " " + "HTTP/1.0" + "\r\n\r\n").encode('utf-8'))
    rec = str(s.recv(4096)), 'utf-8'
    print("RECIEVED DATA!!!!!")
    print("ur data ----------------------->", rec)
    client.close()
    s.close()
    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    print("*" * 50)
    print("[setup_sockets] Implement me!")
    print("*" * 50)
    return None


"""def logic(clientSocket, s, client_address):
    
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.

    while (1) :
        data = clientSocket.recv(1024)
        string = ""
        string += data
        last_char = string[-1]
        if last_char == "\r\n" and data == "\r\n":
            break
    if isinstance(http_request_pipeline(string, client_address), HttpErrorResponse):
        str = HttpErrorResponse.to_byte_array(HttpErrorResponse.to_http_string())
        clientSocket.send(str)
        clientSocket.close()
    if isinstance(http_request_pipeline(string), parse_http_request()):
        IPaddr = s.gethostbyname(string)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(IPaddr, 80)
        s.close()
    print("KKKKKKKKKKKKKKKKKKKK")

    pass
"""
def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    # Return error if needed, then:
    validity = check_http_request_validity(http_raw_data)
    if validity == HttpRequestState.GOOD:
        parse_http_request(source_addr, http_raw_data)

    if validity == HttpRequestState.INVALID_INPUT:

        code = '400'
        message = 'Bad Request'
        object = HttpErrorResponse(code, message)
        object.to_http_string()
        return object
    if validity == HttpRequestState.NOT_SUPPORTED:

        code = '501'
        message = 'Not Implemented'
        object = HttpErrorResponse(code, message)
        object.to_http_string()
        return object

    sanitize_http_request(http_raw_data)
    # Validate, sanitize, return Http object.
    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)
    return None


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    r1 = http_raw_data.split('\n')[0]
    method = r1.split()[0]
    path = r1.split()[1]
    if path == "/":
        r2 = http_raw_data.split('\n')[1]
        host = r2.split()[0]
        if host == "Host:":
            host = re.sub("[:]", "", host)
            r3 = r2.split(':')
            url = r2.split()[1]
            headers = []
            r3 = ' '.join(r3).replace('\r', '').split()
            headers.append(r3)
            headers.append(url)
            headers
            requested_host = headers[0:]
        requested_path = path
    portno = re.findall(r'[0-9]+', r2)
    if portno == []:
        portno = "80"
        requested_port = portno
        requested_host = url
    print("*" * 50)
    print("[parse_http_request] Implement me!")
    print("*" * 50)
    # Replace this line with the correct values.
    request_info = HttpRequestInfo(source_addr, method, requested_host, requested_port, requested_path, headers)
    return request_info


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """

    global version
    r1 = http_raw_data.split('\n')[0]
    r2 = http_raw_data.split('\n')[1]

    if (re.search("GET", r1) != None) and (re.search("/", r1) != None) and (re.search("HTTP/1.0", r1) != None) and (re.search(":", r2)):
        return HttpRequestState.GOOD

    if (re.search("GET", r1) != None) and (re.search("http://", r1) != None) and (re.search("HTTP/1.0", r1) != None):
        return HttpRequestState.GOOD

    if (re.search("GET", r1)!=None) and (re.search("/", r1)!=None) and (re.search("HTTP/1.0",r1)!=None) :
        if (re.search(":", r2) == None) :
            return  HttpRequestState.INVALID_INPUT

    if(re.search("GOAT", r1)!=None):
        return HttpRequestState.INVALID_INPUT

    if (re.search("HEAD"or"POST" or "PUT" , r1)!=None) and (re.search("/",r1)!=None) and (re.search("HTTP/1.0", r1) != None) and (re.search(":", r2)):

        return HttpRequestState.NOT_SUPPORTED

    if (re.search("HEAD"or"POST" or "PUT" ,r1)!=None) and (re.search("/",r1)!=None) and (re.search("HTTP/1.0",r1)!=None):
        return HttpRequestState.INVALID_INPUT

    if (re.search("HEAD"or"POST" or "PUT", r1) != None) and (re.search("HTTP/1.0", r1) == None) and (re.search(":", r2) != None):
        return HttpRequestState.INVALID_INPUT
    print("*" * 50)
    print("[check_http_request_validity] Implement me!")
    print("*" * 50)

    return HttpRequestState.PLACEHOLDER


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """

    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    return request_info

#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)
    #http_request_pipeline(123,"HEAD / HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()