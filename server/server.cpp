#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <fstream> /* for serving the index.html file */
#include <sstream>
#include <unordered_map>
#include "../third_party/sqlite3.h"

#pragma comment(lib, "Ws2_32.lib") // Link with Winsock library

constexpr short MY_PORT = 8080;

// ─────────────────────────────────────────────
// Utility: Trim strings
// ─────────────────────────────────────────────
void trim(std::string &str)
{
    // Trim from beginning
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch)
                                        { return !std::isspace(ch); }));

    // Trim from end
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch)
                           { return !std::isspace(ch); })
                  .base(),
              str.end());
}

// ─────────────────────────────────────────────
// Utility: Create multi-threaded DB connection
// for creating schema and then close.
// ─────────────────────────────────────────────

bool init_db_connection()
{
    /*NOTE: in SQLITE its best practice to open a new connection per request.
    Keeping a global connection in a multithreaded server would require a mutex,
    so this approach avoids concurrency issues and simplifies the design.*/
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2("users.db", &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK)
        return false;

    const char *sql_create_users_table = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    )";

    char *err_msg = nullptr;
    rc = sqlite3_exec(db, sql_create_users_table, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK)
    {
        std::cerr << "[DB] Table creation failed:" << err_msg << "\n";
        free(err_msg);
        return false;
    }
    sqlite3_close(db); // This saves me a headache
    return true;
}

// ─────────────────────────────────────────────
// Core: write user to DB, if not exist.
// ─────────────────────────────────────────────

bool login(const std::string &email, const std::string &password)
{
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2("users.db", &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK)
    {
        std::cout << "[DB] db connection failure: " << sqlite3_errcode(db) << "\n";
        sqlite3_close(db);
        return false;
    }

    /*TODO: code dupl. Move to header file.*/
    const char *sql_select_users = "SELECT 1  FROM users WHERE email = ? AND password = ?;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql_select_users, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        std::cout << "[DB] db connection failure: " << sqlite3_errcode(db) << "\n";
        sqlite3_close(db);
        return false;
    }
    // binding the email and password to (?,?)
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_ROW);

    if (!success)
    {
        std::cout << "[DEBUG] rc is not SQLITE_DONE" << sqlite3_errmsg(db) << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return success;
}

bool register_user(const std::string &email, const std::string &password)
{
    std::cout << "[DEBUG] email and password are " << email.c_str() << " , " << password.c_str() << "\n";
    sqlite3 *db = nullptr; // db handle
    /*Opening connection code block*/
    int rc = sqlite3_open_v2("users.db", &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK)
    {
        std::cout << "[DEBUG] rc ain't SQLITE_OK: 1";
        return false;
    }

    /*Checking if user in users DB already code block*/
    const char *sql_select_users = "SELECT 1 FROM users WHERE email = ?;";
    sqlite3_stmt *stmt;
    /*prepare = Compile SQL into a prepared statement*/
    rc = sqlite3_prepare_v2(db, sql_select_users, -1, &stmt, nullptr);
    if (rc == SQLITE_OK)
    {
        // SAFELY binding email to the statement(email = ?)
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt); // performing the query
        if (rc == SQLITE_ROW)    // if found a match
        {
            sqlite3_finalize(stmt); // Destroy the statement and free memory
            sqlite3_close(db);
            std::cout << "[DEBUG] user with email = " << email << " already exist\n";
            return false;
        }
    }
    else
    {
        std::cout << "[DEBUG] rc ain't SQLITE_OK: 2\n";
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    std::cout << "[DEBUG] not found record. Should be able to create it.\n";
    sqlite3_finalize(stmt); // need to finalize statement as well if not found.
    // Inserting new user
    const char *insert_sql = "INSERT INTO users (email,password) VALUES (?,?);";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        std::cerr << "[DB ERROR]: Prepare failed" << sqlite3_errmsg(db) << "\n";
        sqlite3_close(db);
        return false;
    }
    // binding the email and password to (?,?)
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);

    if (!success)
    {
        std::cout << "[DEBUG] rc is not SQLITE_DONE" << sqlite3_errmsg(db) << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return success;
}

// ─────────────────────────────────────────────
// Utility: Fix relative path
// ─────────────────────────────────────────────

std::string resolve_path(const std::string &path)
{
    if (path.empty() || path == "/")
        return "public/index.html";
    return "public/" + path;
}

/*  --------------------------------------------
    Utility - Determine content type by file ext
    --------------------------------------------  */
std::string get_content_type(const std::string &path)
{
    // std::cout << "path = " << path << "\n";
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos)
        return "application/octet-stream";
    std::string ext = path.substr(dot + 1);
    static const std::unordered_map<std::string, std::string> mimeTypes = {
        {"html", "text/html"},
        {"css", "text/css"},
        {"js", "application/javascript"},
        {"txt", "text/plain"}};
    auto it = mimeTypes.find(ext);
    return it != mimeTypes.end() ? it->second : "application/octet-stream";
}

/*  ----------------------------
    Utility - read file
    ----------------------------  */
std::string read_file(const std::string &filename)
{
    // std::ios::in -> open file for reading. std::ios::binary -> open in binary mode
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        return "";
    std::ostringstream stringStream;
    stringStream << file.rdbuf();
    return stringStream.str();
}

/*  ----------------------------
    Utility - send HTTP response
    ----------------------------  */
void send_response(SOCKET clientSocket, const std::string &body, const std::string &contentType = "text/plain", const std::string &status = "200 OK")
{
    std::string response =
        "HTTP/1.1 " + status + "\r\n" +
        "Content-Type: " + contentType + "\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Connection: close\r\n" +
        "\r\n" +
        body;

    send(clientSocket, response.c_str(), static_cast<int>(response.size()), 0);
}

// ─────────────────────────────────────────────
// Utility: Parse HTTP method and path
// ─────────────────────────────────────────────

void parse_request(const std::string &request, std::string &method, std::string &path)
{
    // std::cout << "\n[DEBUG] prase_request: the request is: " << request << "\n";
    int firstLineEnd = request.find_first_of("\r\n");
    std::string requestLine = request.substr(0, firstLineEnd);
    size_t methodEnd = requestLine.find_first_of(' ');
    size_t pathEnd = requestLine.find_first_of(' ', methodEnd + 1);
    method = request.substr(0, methodEnd);
    path = request.substr(methodEnd + 1, pathEnd - methodEnd);
    trim(method);
    trim(path);
    // size_t bodyStart = request.find("\r\n\r\n") + 4;
    // std::string body = request.substr(bodyStart);
    // std::cout << "[DEBUG] bodyStart = " << bodyStart << "\n";
    // std::cout << "[DEBUG] body = " << body << "\n";
}

// ───────────────────────────────────────────────────────────
// Utility: Extract key-value pairs from POST requests bodies
// ───────────────────────────────────────────────────────────

void parse_form_data(const std::string &body, std::unordered_map<std::string, std::string> &formData)
{
    std::istringstream string_stream(body);
    std::string pair;
    while (std::getline(string_stream, pair, '&'))
    {
        // std::cout << "pair " << pair << "\n";
        size_t eq = pair.find('=');
        if (eq != std::string::npos)
        {
            std::string key = pair.substr(0, eq);
            std::string value = pair.substr(eq + 1);
            // std::cout << "key = " << key;
            // std::cout << ", value = " << value << "\n";
            formData.insert({key, value});
        }
        else
        {
            std::cout << "AHAHAHAH!\n";
        }
    }
}

/*  -----------------------------------------------
    Core - handle a single HTTP request on a thread
    -----------------------------------------------  */
void handle_client(SOCKET clientSocket)
{
    constexpr short BUFF_SIZE = 4096;
    char buffer[BUFF_SIZE];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0)
    {
        std::string request(buffer, bytesReceived);
        std::string method, path;
        parse_request(request, method, path);
        // std::cout << "[DEBUG] Method: '" << method.c_str() << "'\n";
        // std::cout << "[DEBUG] Path: '" << path.c_str() << "'\n";

        // ─────────────────────────────────────
        // Basic Routing Logic
        // ─────────────────────────────────────
        if (method == "GET")
        {
            std::string fileName;
            if (path == "/")
                fileName = "index.html";
            else if (path[0] == '/')
                fileName = path.substr(1);
            std::string ResolvedfileName = resolve_path(fileName);
            std::string fileContents = read_file(ResolvedfileName);
            if (!fileContents.empty())
            {
                std::string contentType = get_content_type(ResolvedfileName);
                send_response(clientSocket, fileContents, contentType);
            }
            else
            {
                send_response(clientSocket, "404 Not Found", "text/plain", "404 Not Found");
            }
        }
        else if (method == "POST")
        {
            size_t contentLengthLoc = request.find("Content-Length");
            std::string x = "Content-Length: ";
            size_t y = x.size();
            std::string contentLength = request.substr(contentLengthLoc + y);
            trim(contentLength);
            size_t bodyStart = request.find("\r\n\r\n") + 4;
            std::string body = request.substr(bodyStart);
            // std::cout << "[DEBUG] bodyStart = " << bodyStart << "\n";
            // std::cout << "[DEBUG] body = " << body << "\n";
            std::string body2 = request.substr(bodyStart, std::stoi(contentLength));
            if (body != body2)
                std::cout << "[DEBUG] Something went wrong body-wise\n";
            std::unordered_map<std::string, std::string> formData;
            parse_form_data(body, formData);
            if (path == "/register")
            {
                std::string email = formData["email"];
                std::string password = formData["password"];
                std::string confirmation_password = formData["confirmation_password"];
                if (register_user(email, password))
                    send_response(clientSocket, "201 User Created.", "text/plain", "201");
                else
                {
                    send_response(clientSocket, "409 Data received, failed to create due to conflict.\n", "text/plain", "409");
                }
            }
            else if (path == "/login")
            {
                std::string email = formData["email"];
                std::string password = formData["password"];
                if (!login(email, password))
                    send_response(clientSocket, "401 Unauthorized\n", "text/plain", "401");
                else
                {
                    send_response(clientSocket, "200 OK\n", "text/plain", "200");
                }
            }
        }
        else
        {
            std::cout << "Method NOT recognized as 'GET'" << "\n";
            send_response(clientSocket, "405 Method not allowed\n", "text/plain", "405 Method not allowed");
        }
    }
    closesocket(clientSocket);
    std::cout << "[Thread " << std::this_thread::get_id() << "] Connection closed.\n";
}

int main()
{
    /* Initialize Winsock */
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0)
    {
        std::cerr << "WSAStartup failure: " << wsaResult << "\n";
    }
    /* Create a socket */
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET)
    {
        std::cerr << "Socket Creation Failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }
    /* Bind to port 8080 */
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
    serverAddr.sin_port = htons(MY_PORT);

    if (bind(serverSocket, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Bind failure: " << WSAGetLastError() << "\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    /*Creating DB schemas*/
    if (!init_db_connection())
    {
        std::cerr << "[DEBUG] failed to initialize DB. Exiting 1...\n";
        return 1;
    }

    /* Listen for incoming requests */
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "Listen failed! " << WSAGetLastError() << "\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port " << MY_PORT << "\n";

    std::vector<std::thread> threadPool;
    while (true)
    {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET)
        {
            std::cerr << "Accept failed: " << WSAGetLastError() << "\n";
            break;
        }
        /* spawn a view thread for the client */
        threadPool.emplace_back(handle_client, clientSocket);
    }
    /* cleanup*/
    for (auto &t : threadPool)
    {
        if (t.joinable())
            t.join();
    }
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}