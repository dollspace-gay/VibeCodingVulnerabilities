// sysstats_mqtt.cpp
// Build: see instructions below
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/statvfs.h>

#include <mqtt/async_client.h>

static volatile std::sig_atomic_t g_stop = 0;
void signal_handler(int) { g_stop = 1; }

// ---------- Helpers ----------
struct CpuTimes { unsigned long long idle=0, total=0; };

std::optional<CpuTimes> read_cpu_times() {
    std::ifstream f("/proc/stat");
    if (!f) return std::nullopt;
    std::string cpu;
    unsigned long long user, nice_, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    // First line starts with "cpu "
    if (!(f >> cpu >> user >> nice_ >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice))
        return std::nullopt;
    CpuTimes t;
    t.idle = idle + iowait;
    t.total = user + nice_ + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
    return t;
}

double compute_cpu_util(const CpuTimes& prev, const CpuTimes& curr) {
    const double d_total = static_cast<double>(curr.total - prev.total);
    const double d_idle  = static_cast<double>(curr.idle  - prev.idle);
    if (d_total <= 0.0) return 0.0;
    double util = (1.0 - (d_idle / d_total)) * 100.0;
    if (util < 0.0) util = 0.0;
    if (util > 100.0) util = 100.0;
    return util;
}

struct MemInfo { unsigned long long total_kb=0, available_kb=0; };

std::optional<MemInfo> read_meminfo() {
    std::ifstream f("/proc/meminfo");
    if (!f) return std::nullopt;
    MemInfo mi;
    std::string key, unit;
    unsigned long long val;
    while (f >> key >> val >> unit) {
        if (key == "MemTotal:") mi.total_kb = val;
        else if (key == "MemAvailable:") mi.available_kb = val;
    }
    if (mi.total_kb == 0) return std::nullopt;
    return mi;
}

struct DiskInfo { double used_pct=0.0; unsigned long long total_bytes=0, used_bytes=0; };

std::optional<DiskInfo> read_disk_usage(const std::string& path) {
    struct statvfs s{};
    if (statvfs(path.c_str(), &s) != 0) return std::nullopt;
    unsigned long long total = static_cast<unsigned long long>(s.f_blocks) * s.f_frsize;
    unsigned long long avail = static_cast<unsigned long long>(s.f_bavail) * s.f_frsize; // unprivileged available
    unsigned long long used  = total > avail ? total - avail : 0ULL;
    double used_pct = (total == 0) ? 0.0 : (static_cast<double>(used) / static_cast<double>(total)) * 100.0;
    DiskInfo d{used_pct, total, used};
    return d;
}

std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '\"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                    o << "\\u" << std::hex << std::uppercase << (int)c;
                else
                    o << c;
        }
    }
    return o.str();
}

std::string get_hostname() {
    char buf[256];
    if (gethostname(buf, sizeof(buf)) != 0) return "unknown";
    buf[sizeof(buf)-1] = '\0';
    return std::string(buf);
}

std::string getenv_or(const char* key, const std::string& defv) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : defv;
}

struct Config {
    std::string broker;     // e.g. tcp://localhost:1883
    std::string topic;      // e.g. stats/<hostname>
    std::string client_id;
    std::string username;
    std::string password;
    int qos = 1;
    int interval_sec = 30;
    std::string disk_path = "/";
    bool retain = false;
};

void print_usage(const char* prog) {
    std::cerr <<
    "Usage: " << prog << " [options]\n"
    "Options (env var override in parentheses):\n"
    "  --broker <uri>        MQTT broker URI (MQTT_BROKER), default tcp://localhost:1883\n"
    "  --topic <topic>       MQTT topic (MQTT_TOPIC), default stats/<hostname>\n"
    "  --client-id <id>      Client ID (MQTT_CLIENT_ID), default sysstats-<hostname>\n"
    "  --username <user>     Username (MQTT_USERNAME)\n"
    "  --password <pass>     Password (MQTT_PASSWORD)\n"
    "  --qos <0|1|2>         QoS, default 1\n"
    "  --interval <sec>      Interval seconds, default 30\n"
    "  --disk-path <path>    Filesystem path to measure, default /\n"
    "  --retain              Publish retained messages\n"
    "  -h, --help            Show this help\n";
}

Config parse_config(int argc, char** argv) {
    Config c;
    auto host = get_hostname();

    c.broker     = getenv_or("MQTT_BROKER", "tcp://localhost:1883");
    c.topic      = getenv_or("MQTT_TOPIC",  "stats/" + host);
    c.client_id  = getenv_or("MQTT_CLIENT_ID", "sysstats-" + host);
    c.username   = getenv_or("MQTT_USERNAME", "");
    c.password   = getenv_or("MQTT_PASSWORD", "");
    c.disk_path  = getenv_or("DISK_PATH", "/");

    for (int i=1; i<argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* what)->std::string{
            if (i+1 >= argc) { std::cerr << "Missing value for " << what << "\n"; std::exit(2); }
            return std::string(argv[++i]);
        };
        if (a == "--broker") c.broker = need("--broker");
        else if (a == "--topic") c.topic = need("--topic");
        else if (a == "--client-id") c.client_id = need("--client-id");
        else if (a == "--username") c.username = need("--username");
        else if (a == "--password") c.password = need("--password");
        else if (a == "--qos") c.qos = std::stoi(need("--qos"));
        else if (a == "--interval") c.interval_sec = std::stoi(need("--interval"));
        else if (a == "--disk-path") c.disk_path = need("--disk-path");
        else if (a == "--retain") c.retain = true;
        else if (a == "-h" || a == "--help") { print_usage(argv[0]); std::exit(0); }
        else { std::cerr << "Unknown option: " << a << "\n"; print_usage(argv[0]); std::exit(2); }
    }
    return c;
}

// ---------- Main ----------
int main(int argc, char** argv) {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    Config cfg = parse_config(argc, argv);

    mqtt::async_client cli(cfg.broker, cfg.client_id);

    mqtt::connect_options_builder cob;
    if (!cfg.username.empty()) cob.user_name(cfg.username);
    if (!cfg.password.empty()) cob.password(cfg.password);
    // Auto-reconnect with backoff
    mqtt::connect_options connOpts = cob.automatic_reconnect(true)->clean_session(true).finalize();

    try {
        std::cout << "Connecting to " << cfg.broker << " as " << cfg.client_id << "...\n";
        cli.connect(connOpts)->wait();
        std::cout << "Connected.\n";
    } catch (const mqtt::exception& e) {
        std::cerr << "MQTT connect failed: " << e.what() << "\n";
        return 1;
    }

    // Prime CPU baseline
    auto prev = read_cpu_times();
    if (!prev) {
        std::cerr << "Failed to read /proc/stat\n";
        return 1;
    }

    // Take a short initial delta so first publish has a CPU% based on ~1s window
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto curr = read_cpu_times();
    if (curr) prev = curr;

    while (!g_stop) {
        auto t_start = std::chrono::steady_clock::now();

        // Read CPU twice around interval to compute deltas over the loop
        auto prevCpu = read_cpu_times();
        if (!prevCpu) { std::cerr << "Failed to read /proc/stat\n"; break; }

        // Sleep for (interval) while also honoring early signals
        for (int s=0; s<cfg.interval_sec && !g_stop; ++s)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_stop) break;

        auto currCpu = read_cpu_times();
        if (!currCpu) { std::cerr << "Failed to read /proc/stat\n"; break; }
        double cpu_pct = compute_cpu_util(*prevCpu, *currCpu);

        auto mem = read_meminfo();
        double mem_pct = 0.0;
        unsigned long long mem_total=0, mem_used=0;
        if (mem) {
            mem_total = mem->total_kb * 1024ULL;
            unsigned long long mem_avail = mem->available_kb * 1024ULL;
            mem_used = mem_total > mem_avail ? mem_total - mem_avail : 0ULL;
            mem_pct = (mem_total == 0) ? 0.0 : (static_cast<double>(mem_used) / static_cast<double>(mem_total)) * 100.0;
        }

        auto disk = read_disk_usage(cfg.disk_path);
        double disk_pct = disk ? disk->used_pct : 0.0;

        // Build JSON
        std::ostringstream js;
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        std::string host = get_hostname();

        js << "{"
           << "\"host\":\"" << json_escape(host) << "\","
           << "\"timestamp_ms\":" << ms << ","
           << "\"cpu_pct\":" << std::fixed << std::setprecision(2) << cpu_pct << ","
           << "\"mem_pct\":" << std::fixed << std::setprecision(2) << mem_pct << ","
           << "\"mem_total_bytes\":" << mem_total << ","
           << "\"mem_used_bytes\":" << mem_used << ",";
        if (disk) {
            js << "\"disk\":{"
               << "\"path\":\"" << json_escape(cfg.disk_path) << "\","
               << "\"used_pct\":" << std::fixed << std::setprecision(2) << disk->used_pct << ","
               << "\"total_bytes\":" << disk->total_bytes << ","
               << "\"used_bytes\":" << disk->used_bytes
               << "}";
        } else {
            js << "\"disk\":null";
        }
        js << "}";

        auto payload = js.str();

        try {
            mqtt::message_ptr msg = mqtt::make_message(cfg.topic, payload);
            msg->set_qos(cfg.qos);
            msg->set_retained(cfg.retain);
            cli.publish(msg)->wait();
            std::cout << "Published to " << cfg.topic << ": " << payload << "\n";
        } catch (const mqtt::exception& e) {
            std::cerr << "Publish failed: " << e.what() << "\n";
        }
    }

    try {
        cli.disconnect()->wait();
        std::cout << "Disconnected.\n";
    } catch (...) {
        // ignore
    }
    return 0;
}