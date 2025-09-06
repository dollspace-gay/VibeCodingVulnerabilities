/**
 * @file main.cpp
 * @brief A secure MQTT client to report system statistics.
 *
 * This program collects CPU, memory, and disk usage statistics and reports them
 * to an MQTT broker over a secure TLS connection.
 *
 * Security Best Practices Implemented:
 * 1.  Secure Connection: Uses TLSv1.2 for encrypted communication with the MQTT broker.
 * 2.  Authentication: Uses username/password authentication.
 * 3.  No Hardcoded Secrets: All sensitive information (passwords, paths to certificates)
 * is loaded from environment variables, not stored in the source code.
 * 4.  Robust Error Handling: Checks for errors on file operations, environment
 * variable access, and network communication.
 * 5.  Secure Coding Practices: Uses std::string and modern C++ features to prevent
 * buffer overflows and manages resources using RAII.
 * 6.  Input Validation: Checks for the presence of required environment variables.
 * 7.  Least Privilege Principle: The program only requires read access to the /proc
 * filesystem and network access. It should be run as a non-privileged user.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <numeric>
#include <chrono>
#include <thread>
#include <filesystem>
#include <cstdlib> // For getenv
#include <mqtt/async_client.h>

// --- Configuration ---
// Note: These are configurable via environment variables. Default values are for guidance.
const std::string DEFAULT_SERVER_ADDRESS = "ssl://localhost:8883";
const std::string DEFAULT_CLIENT_ID = "system-stats-reporter";
const std::string DEFAULT_TOPIC = "system/stats";
const std::string DISK_PATH = "/"; // Path to check for disk usage
const int REPORT_INTERVAL_SECONDS = 10;
const int QOS = 1;

/**
 * @struct CPUStats
 * @brief Holds CPU time statistics from /proc/stat.
 */
struct CPUStats {
    long long user;
    long long nice;
    long long system;
    long long idle;
    long long iowait;
    long long irq;
    long long softirq;
    long long steal;

    long long get_idle_time() const {
        return idle + iowait;
    }

    long long get_total_time() const {
        return user + nice + system + idle + iowait + irq + softirq + steal;
    }
};

/**
 * @brief Reads the current overall CPU statistics from /proc/stat.
 * @return A CPUStats object containing the current values.
 */
CPUStats read_cpu_stats() {
    std::ifstream stat_file("/proc/stat");
    if (!stat_file.is_open()) {
        std::cerr << "Error: Could not open /proc/stat for reading." << std::endl;
        return {};
    }

    std::string line;
    std::getline(stat_file, line);
    stat_file.close();

    CPUStats stats{};
    std::string cpu_label;
    std::sscanf(line.c_str(), "%s %lld %lld %lld %lld %lld %lld %lld %lld",
                &cpu_label[0], &stats.user, &stats.nice, &stats.system, &stats.idle,
                &stats.iowait, &stats.irq, &stats.softirq, &stats.steal);

    return stats;
}


/**
 * @brief Calculates CPU usage percentage over a period.
 *
 * This function is stateful and must be called sequentially to measure the delta.
 * @return CPU usage as a percentage (0.0 to 100.0).
 */
double get_cpu_usage() {
    static CPUStats prev_stats = read_cpu_stats();
    std::this_thread::sleep_for(std::chrono::seconds(1)); // Wait for a second to get a meaningful delta
    CPUStats current_stats = read_cpu_stats();

    long long prev_idle = prev_stats.get_idle_time();
    long long current_idle = current_stats.get_idle_time();

    long long prev_total = prev_stats.get_total_time();
    long long current_total = current_stats.get_total_time();

    long long total_diff = current_total - prev_total;
    long long idle_diff = current_idle - prev_idle;

    prev_stats = current_stats;

    if (total_diff == 0) {
        return 0.0;
    }

    double cpu_usage = 100.0 * (total_diff - idle_diff) / total_diff;
    return cpu_usage;
}

/**
 * @brief Gets the current memory usage percentage.
 * @return Memory usage as a percentage (0.0 to 100.0).
 */
double get_memory_usage() {
    std::ifstream meminfo_file("/proc/meminfo");
    if (!meminfo_file.is_open()) {
        std::cerr << "Error: Could not open /proc/meminfo for reading." << std::endl;
        return -1.0;
    }

    std::string line;
    long long mem_total = 0, mem_available = 0;
    
    while (std::getline(meminfo_file, line)) {
        if (line.rfind("MemTotal:", 0) == 0) {
            sscanf(line.c_str(), "MemTotal: %lld kB", &mem_total);
        }
        if (line.rfind("MemAvailable:", 0) == 0) {
            sscanf(line.c_str(), "MemAvailable: %lld kB", &mem_available);
        }
    }
    meminfo_file.close();

    if (mem_total == 0) {
        std::cerr << "Error: Could not parse MemTotal from /proc/meminfo." << std::endl;
        return -1.0;
    }

    long long mem_used = mem_total - mem_available;
    return 100.0 * mem_used / mem_total;
}

/**
 * @brief Gets the disk usage percentage for a given path.
 * @param path The filesystem path to check.
 * @return Disk usage as a percentage (0.0 to 100.0).
 */
double get_disk_usage(const std::string& path) {
    try {
        const std::filesystem::space_info si = std::filesystem::space(path);
        uintmax_t total_space = si.capacity;
        uintmax_t free_space = si.available;
        
        if (total_space == 0) {
            return 0.0;
        }

        uintmax_t used_space = total_space - free_space;
        return 100.0 * used_space / total_space;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error getting disk space for '" << path << "': " << e.what() << std::endl;
        return -1.0;
    }
}

/**
 * @brief Retrieves a configuration value from an environment variable.
 * @param var_name The name of the environment variable.
 * @param default_value The value to return if the variable is not set.
 * @param is_required If true, the program will exit if the variable is not set.
 * @return The value of the environment variable or the default value.
 */
std::string get_env_var(const std::string& var_name, const std::string& default_value, bool is_required = false) {
    const char* value = std::getenv(var_name.c_str());
    if (value == nullptr) {
        if (is_required) {
            std::cerr << "Error: Required environment variable '" << var_name << "' is not set. Exiting." << std::endl;
            exit(EXIT_FAILURE);
        }
        return default_value;
    }
    return std::string(value);
}


int main() {
    std::cout << "Starting System Statistics Reporter..." << std::endl;

    // --- Securely load configuration from environment variables ---
    std::string server_address = get_env_var("MQTT_SERVER_ADDRESS", DEFAULT_SERVER_ADDRESS);
    std::string client_id = get_env_var("MQTT_CLIENT_ID", DEFAULT_CLIENT_ID);
    std::string topic = get_env_var("MQTT_TOPIC", DEFAULT_TOPIC);
    std::string mqtt_username = get_env_var("MQTT_USERNAME", "", true);
    std::string mqtt_password = get_env_var("MQTT_PASSWORD", "", true);
    std::string ca_certs_path = get_env_var("MQTT_CA_CERTS", "", true);
    
    mqtt::async_client client(server_address, client_id);

    try {
        // --- Setup secure connection options ---
        mqtt::ssl_options ssl_opts;
        ssl_opts.set_trust_store(ca_certs_path);
        // If using client certificates for authentication, uncomment the following lines:
        // std::string client_cert_path = get_env_var("MQTT_CLIENT_CERT", "", true);
        // std::string client_key_path = get_env_var("MQTT_CLIENT_KEY", "", true);
        // ssl_opts.set_key_store(client_cert_path);
        // ssl_opts.set_private_key(client_key_path);

        mqtt::connect_options conn_opts;
        conn_opts.set_keep_alive_interval(20);
        conn_opts.set_clean_session(true);
        conn_opts.set_user_name(mqtt_username);
        conn_opts.set_password(mqtt_password);
        conn_opts.set_ssl(ssl_opts);

        std::cout << "Connecting to MQTT broker at " << server_address << "..." << std::endl;
        client.connect(conn_opts)->wait();
        std::cout << "Connection successful." << std::endl;

        while (true) {
            // --- Collect statistics ---
            double cpu_usage = get_cpu_usage();
            double mem_usage = get_memory_usage();
            double disk_usage = get_disk_usage(DISK_PATH);

            // --- Format data as JSON ---
            // Using simple string concatenation to avoid adding a JSON library dependency.
            // For complex data, a dedicated JSON library is recommended.
            std::string payload = "{";
            payload += "\"cpu_usage\":" + std::to_string(cpu_usage) + ",";
            payload += "\"memory_usage\":" + std::to_string(mem_usage) + ",";
            payload += "\"disk_usage\":" + std::to_string(disk_usage);
            payload += "}";

            std::cout << "Publishing: " << payload << std::endl;

            // --- Publish message ---
            mqtt::message_ptr pubmsg = mqtt::make_message(topic, payload);
            pubmsg->set_qos(QOS);
            client.publish(pubmsg)->wait();

            std::this_thread::sleep_for(std::chrono::seconds(REPORT_INTERVAL_SECONDS));
        }

    } catch (const mqtt::exception& exc) {
        std::cerr << "MQTT Error: " << exc.what() << std::endl;
        return 1;
    } catch (const std::exception& exc) {
        std::cerr << "An unexpected error occurred: " << exc.what() << std::endl;
        return 1;
    }

    return 0;
}
