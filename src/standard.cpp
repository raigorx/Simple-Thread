#include <cstdlib>
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

void thread_func(int value) {
  cout << "Thread started with value: " << value << '\n';
  this_thread::sleep_for(chrono::seconds(2));  //  Sleep for 2 seconds
  cout << "Thread finished after 2 seconds.\n";
}

int main() {

  //  Create a thread that will execute thread_func
  thread my_thread0(thread_func, 10);
  //  Create a thread that will execute thread_func
  thread my_thread1(thread_func, 20);

  //  Main thread continues to execute
  cout << "Main thread continues to execute.\n";

  //  Wait for the thread to finish execution
  my_thread0.join();
  my_thread1.join();

  cout << "Main thread finished after waiting for the other thread.\n";
  return EXIT_SUCCESS;
}
