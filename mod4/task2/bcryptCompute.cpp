#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <crypt.h>      // crypt_r library
#include <sys/stat.h>  
#include <chrono>

#define THREAD_COUNT 8

// globals
std::atomic<bool> stopRequested(false);
std::string foundPassword;
std::mutex foundPasswordMutex;

// Entry type
typedef struct Entry {
    std::string user;
    std::string bcryptInfo; // full stored bcrypt string, e.g. "$2b$08$<salt><hash>"
} Entry;

static long long file_size_bytes(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return -1;
    return static_cast<long long>(st.st_size);
}

// Examples: "5 seconds."  "5 seconds. 10 minutes."  "5 seconds. 10 minutes. 1 hours."
static std::string format_elapsed(double total_seconds) {
    long long secs = static_cast<long long>(total_seconds + 0.5); // round seconds
    long long hrs = secs / 3600;
    secs %= 3600;
    long long mins = secs / 60;
    secs %= 60;

    std::ostringstream ss;
    ss << secs << " seconds.";
    if (mins > 0) ss << " " << mins << " minutes.";
    if (hrs > 0) ss << " " << hrs << " hours.";
    return ss.str();
}

// Terminate helper: stores optional pwd, prints msg once, and requests stop.
static void terminate_with_message(const std::string &msg, std::string_view pwd = {}) {
    std::lock_guard<std::mutex> lk(foundPasswordMutex);
    if (stopRequested.load(std::memory_order_acquire)) return;
    if (!pwd.empty()) foundPassword = std::string(pwd);
    std::cout << msg << std::endl;
    stopRequested.store(true, std::memory_order_release);
}

// Function for a thread to compute b_crypt hashes refering to wordlistPath,
// starting at start, end at end, entry contains the hash info to crack
static void worker_chunk(const std::string& wordlistPath,
                        std::streampos start, std::streampos end, Entry entry)
{
    std::ifstream wordList(wordlistPath, std::ios::binary);
    if (!wordList) {
        terminate_with_message("failed to open wordList");
        return;
    }

    wordList.seekg(start);
    if (!wordList) {
        terminate_with_message("failed to seek wordList");
        return;
    }

    if (start > 0) {
        std::string discard;
        std::getline(wordList, discard); // skip partial line
    }

    std::string candidate;
    struct crypt_data cd{};
    cd.initialized = 0;

    while (!stopRequested.load(std::memory_order_acquire) && std::getline(wordList, candidate)) {
        std::streampos pos = wordList.tellg();
        if (pos == std::streampos(-1)) break;
        if (pos > end) break;
        if (candidate.empty()) continue;

        char* out = crypt_r(candidate.c_str(), entry.bcryptInfo.c_str(), &cd);
        if (!out) {
            terminate_with_message(std::string("crypt_r error for user '") + entry.user + "'");
            break;
        }

        if (std::string(out) == entry.bcryptInfo) {
            terminate_with_message(std::string("Found for ") + entry.user + ": " + candidate, std::string_view(candidate));
            break;
        }
    }
}

int main() {
    const std::string shadowFile  = "shadow.txt";
    const std::string wordlist    = "nltk_corpus.txt";
    const std::string outputFile  = "passwords.txt";
    const int startLineNum = 3;

    // parse shadow file, containing the hashes+salt of users whose pw we want to crack
    std::ifstream in(shadowFile);
    if (!in) {
        std::cerr << "Error: could not open " << shadowFile << "\n";
        return 1;
    }

    //store info from the input shadow file into entries
    std::vector<Entry> entries;
    std::string line;
    int curLine = 0;
    while (std::getline(in, line)) {
        if (curLine++ < startLineNum) continue;
        if (line.empty()) continue;
        std::istringstream ss(line);
        Entry e;
        std::getline(ss, e.user, ':');
        std::getline(ss, e.bcryptInfo);
        if (e.bcryptInfo.empty()) {
            std::cerr << "Skipping bad line " << (curLine - 1) << "\n";
            continue;
        }
        entries.push_back(e);
    }
    if (entries.empty()) {
        std::cout << "No entries to process.\n";
        return 0;
    }

    std::ofstream out(outputFile, std::ios::app);
    if (!out) {
        std::cerr << "Error opening output file\n";
        return 1;
    }

    long long totalBytes = file_size_bytes(wordlist);
    if (totalBytes <= 0) {
        std::cerr << "Could not stat wordlist\n";
        return 1;
    }

    for (const Entry& ent : entries) {  //for each pw
        stopRequested.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(foundPasswordMutex);
            foundPassword.clear();
        }

        std::thread workers[THREAD_COUNT];

        //start timer to track how long it take
        auto t0 = std::chrono::steady_clock::now();

        //start the workers
        for (int i = 0; i < THREAD_COUNT; ++i) {
            long long s = (totalBytes * i) / THREAD_COUNT;
            long long epos = (totalBytes * (i + 1)) / THREAD_COUNT; //record start time for this pw
            workers[i] = std::thread(worker_chunk,
                                     wordlist,
                                     static_cast<std::streampos>(s),
                                     static_cast<std::streampos>(epos),
                                     ent); 
        }
        //join workers
        for (int i = 0; i < THREAD_COUNT; ++i) {
            if (workers[i].joinable()) workers[i].join();
        }

        //record how long it took
        auto t1 = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = t1 - t0;
        std::string elapsed_str = format_elapsed(elapsed.count());

        //print results
        {
            std::lock_guard<std::mutex> lk(foundPasswordMutex);
            if (!foundPassword.empty()) {
                std::cout << "Found for " << ent.user
                          << " (time=" << elapsed_str << "): " << foundPassword << "\n";
                out << ent.user << " " << foundPassword << " " << elapsed_str << "\n";
                out.flush();
            } else {
                std::cout << "Not found for " << ent.user
                          << " (time=" << elapsed_str << ")\n";
            }
        }
    }

    return 0;
}
