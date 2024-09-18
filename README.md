# secure-endpoint-ebpf

This repo contains the network, file, and process monitoring eBPF programs used by the Cisco Secure Endpoint linux connector to detect various events on the system.

- [FileProc](bcc/SeEbpfFileProcProgram.c) tracks file and process information
- [NetworkMonitor](bcc/SeEbpfNetworkMonitorProgram.c) tracks various networking events

For more information about Cisco Secure Endpoint please visit the product page [here](https://www.cisco.com/site/us/en/products/security/endpoint-security/secure-endpoint/index.html).

## Building
This code cannot be directly built, it must be loaded into the Linux kernel through eBPF. One of the easiest and most straightforward ways to do this is to use Python bindings provided by [BCC](https://github.com/iovisor/bcc). 

This is an example of how this can be done in Python once BCC is installed: 
```python
from bcc import BPF
import os

bpftext = R"""
<copy eBPF code from files here>
"""

b = BPF(text=bpftext)

# each kprobe must be attached, most of the functions in the files attach to a kprobe
# using attach_kprobe where "event" is the name of the event you want to attach the kprobe to 
# and "fn_name" is the name of the function in the ebpf program.
# below is an example for the fput_probe
b.attach_kprobe(event="__fput", fn_name="__fput_probe")

# the easiest way to get output from/debug the code is by inserting the bpf_trace_printk() 
# helper into the ebpf code. bpf_trace_printk() statements are similar to printf() and
# can be read using 
b.trace_print()

```

## Issues and contributions
We use GitHub to track issues and accept contributions. If you'd like to raise an issue or open a pull request with changes, refer to our [contribution guide](docs/CONTRIBUTING.md).

## More Resources

Here are some additional resources on what eBPF is and how to get started.
- [Linux Man Page](https://man7.org/linux/man-pages/man2/bpf.2.html)
- General information on eBPF and upcoming developements: [ebpf.io](https://ebpf.io)
- Some examples on eBPF program creation: [How to turn any syscall into an event: Introducing eBPF Kernel probes](https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/)
- Toolkit to simplify creating and loading eBPF programs: [BCC](https://github.com/iovisor/bcc)

## License
Distributed under the LGPL-2.1 License. See [LICENSE](LICENSE) for more information

