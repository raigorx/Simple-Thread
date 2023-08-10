add_rules("mode.debug", "mode.release", "mode.asan", "mode.check", "mode.tsan", "mode.lsan" ,"mode.ubsan","mode.valgrind")
add_rules("plugin.vsxmake.autoupdate")
add_rules("plugin.compile_commands.autoupdate")

set_languages("c17", "c++20")

set_warnings("allextra")

add_cxxflags("cl::/Za")

if is_mode("debug") then
  -- this include ucrtbased.dll in the binary
  add_cxxflags("cl::/MDd")
end

if is_plat("windows") then
  target("win_api_thread")
    set_kind("binary")
    add_files("src/windows.cpp")
end

target("standard")
  set_kind("binary")
  add_files("src/standard.cpp")