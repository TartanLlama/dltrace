#include "elf/elf++.hh"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <string>
#include <set>
#include <elf.h>
#include <link.h>

using addr_t = std::uintptr_t;

class breakpoint {
public:
    breakpoint() : m_pid{0}, m_addr{0}, m_enabled{false}, m_saved_data{0} {}
    breakpoint(pid_t pid, addr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

    void enable() {
        auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
        m_saved_data = static_cast<uint8_t>(data & 0xff); //save bottom byte
        uint64_t int3 = 0xcc;
        uint64_t data_with_int3 = ((data & ~0xff) | int3); //set bottom byte to 0xcc
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

        m_enabled = true;
    }

    void disable() {
        auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
        auto restored_data = ((data & ~0xff) | m_saved_data);
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

        m_enabled = false;
    }

    bool is_enabled() const { return m_enabled; }

    auto get_address() const -> std::intptr_t { return m_addr; }
private:
    pid_t m_pid;
    addr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data; //data which used to be at the breakpoint address
};

struct lib_info {
    lib_info (std::string name, addr_t addr)
        : name{std::move(name)}, addr{addr}
    {}
    const std::string name;
    const addr_t addr;
};

bool operator< (lib_info const& lhs, lib_info const& rhs) {
    return std::tie(lhs.name, lhs.addr) < std::tie(rhs.name, rhs.addr);
}

class tracer {
public:
    tracer(pid_t pid, std::string const& file_name)
        : m_pid{pid} {
        auto fd = open(file_name.c_str(), O_RDONLY);
        m_elf = elf::elf {elf::create_mmap_loader(fd)};
    }

    void trace();

private:
    void wait_for_signal();
    void resolve_rendezvous();
    void update_libraries();
    uint64_t read_word(addr_t& addr);
    std::string read_string(addr_t& addr);
    template <class T>
    T read_from_inferior(addr_t& addr);
    addr_t get_pc();
    void set_pc(addr_t pc);

    pid_t m_pid;
    elf::elf m_elf;
    std::set<lib_info> m_libraries{};
    addr_t m_rendezvous_addr = 0;
    breakpoint m_entry_breakpoint;
    breakpoint m_linker_breakpoint;
};

uint64_t tracer::read_word(addr_t& addr) {
    return read_from_inferior<uint64_t>(addr);
}

std::string tracer::read_string(addr_t& start_addr) {
    auto addr = start_addr;
    std::string str = "";

    auto word = read_word(addr);
    while (true) {
        auto word_ptr = reinterpret_cast<unsigned char*>(&word);

        for (int i = 0; i < 8; ++i) {
            if (word_ptr[i]) {
                str += word_ptr[i];
            }
            else {
                start_addr = addr + i;
                return str;
            }
        }
        word = read_word(addr);
    }

    return str;
}

template <class T>
T tracer::read_from_inferior(addr_t& addr) {
    T t;
    iovec local_iov {&t, sizeof(T)};
    iovec remote_iov {(void*)addr, sizeof(T)};
    process_vm_readv(m_pid, &local_iov, 1, &remote_iov, 1, 0);
    addr += sizeof(T);
    return t;
}

addr_t tracer::get_pc() {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    return regs.rip;
}

void tracer::set_pc(addr_t pc) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    regs.rip = pc;
    ptrace(PTRACE_SETREGS, m_pid, nullptr, &regs);
}


void tracer::resolve_rendezvous() {
    auto dyn_section = m_elf.get_section(".dynamic");
    auto addr = dyn_section.get_hdr().addr;
    auto val = read_word(addr);

    while (val != 0) {
        if (val == DT_DEBUG) {
            auto rend_addr = read_word(addr);
            m_rendezvous_addr = rend_addr;
            auto rendezvous = read_from_inferior<r_debug>(rend_addr);
            m_linker_breakpoint = breakpoint{m_pid, rendezvous.r_brk};
            m_linker_breakpoint.enable();
            return;
        }

        val = read_word(addr);
    }

    std::cerr << "Could not resolve rendezvous structure\n";
    exit(-1);
}


void tracer::update_libraries() {
    if (!m_rendezvous_addr) {
        resolve_rendezvous();
    }

    std::set<lib_info> new_libs{};
    auto rend_addr = m_rendezvous_addr;
    auto rendezvous = read_from_inferior<r_debug>(rend_addr);
    auto link_map_addr = rendezvous.r_map;

    while (link_map_addr) {
        auto addr = reinterpret_cast<addr_t>(link_map_addr);
        auto map = read_from_inferior<link_map>(addr);
        auto name_addr = (uint64_t)map.l_name;
        auto name = read_string(name_addr);
        if (name != "") {
            new_libs.emplace(name, map.l_addr);
        }
        link_map_addr = map.l_next;
    }

    std::vector<lib_info> loaded;
    std::vector<lib_info> unloaded;

    std::set_difference(m_libraries.begin(), m_libraries.end(),
                        new_libs.begin(), new_libs.end(),
                        std::back_inserter(unloaded));
    std::set_difference(new_libs.begin(), new_libs.end(),
                        m_libraries.begin(), m_libraries.end(),
                        std::back_inserter(loaded));

    for (auto&& lib : loaded) {
        std::cout << "Loaded " << lib.name << " at 0x" << std::hex << lib.addr << std::endl;
    }

    for (auto&& lib : unloaded) {
        std::cout << "Unloaded " << lib.name << " at 0x" << std::hex << lib.addr << std::endl;
    }

    m_libraries = new_libs;
}

void tracer::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    if (WIFEXITED(wait_status)) {
        std::cout << "Process exited\n";
        exit(0);
    }

    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);

    if (info.si_signo == SIGTRAP) {
        if (m_entry_breakpoint.is_enabled()) {
            if (get_pc() == m_entry_breakpoint.get_address() + 1) {
                update_libraries();
                m_entry_breakpoint.disable();
                set_pc(get_pc()-1);
            }
        }
        else if (get_pc() == m_linker_breakpoint.get_address() + 1) {
            update_libraries();
            set_pc(get_pc()-1);
            m_linker_breakpoint.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            int wait_status;
            auto options = 0;
            waitpid(m_pid, &wait_status, options);
            m_linker_breakpoint.enable();
        }
    }
}

void tracer::trace() {
    ptrace(PTRACE_SETOPTIONS, m_pid, nullptr, PTRACE_O_TRACEEXIT);

    wait_for_signal();
    auto entry_point = m_elf.get_hdr().entry;
    m_entry_breakpoint = breakpoint{m_pid, entry_point};
    m_entry_breakpoint.enable();

    while (true) {
        ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
        wait_for_signal();
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //child
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            std::cerr << "Error in ptrace\n";
            return -1;
        }
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1)  {
        //parent
        tracer tr {pid, prog};
        tr.trace();
    }

}
