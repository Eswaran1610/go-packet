# Go Packet Explorer

A Linux-first, GUI-based network packet explorer built with **Go**,
**Fyne**, **gopacket**, and **libpcap**.

The goal is to make packet capture easier to inspect and
understand---not merely to wrap the `tcpdump` command in a GUI.

> **Status:** Phase 1 prototype / learning project. Not yet intended as
> an office-ready packet analyzer.

## Project goals

-   Capture live packets from a selected network interface.
-   Display packet summaries in a desktop GUI.
-   Inspect decoded packet fields.
-   Learn networking by connecting theory, packet captures, diagrams,
    and Go code.
-   Grow incrementally into a more capable analysis tool.

## Architecture

``` text
Linux network interface
        |
      libpcap
        |
 Go capture goroutine
        |
 gopacket packet decoder
        |
 packet-processing pipeline
        |
      Fyne GUI
  packet list + details
```

### Responsibilities

  Component              Responsibility
  ---------------------- -------------------------------------------------
  Linux interface        Source of traffic visible to the capture host
  libpcap                Provides packet-capture access
  gopacket               Decodes captured bytes into protocol layers
  Go capture goroutine   Reads packets without blocking the GUI
  Fyne                   Renders the desktop interface and user controls

The GUI should not perform blocking capture work. Capture and packet
processing should run separately, with updates delivered safely to the
GUI.

## Technology stack

-   **Go** --- application language
-   **Fyne v2** --- native desktop GUI
-   **gopacket** --- packet decoding and libpcap integration
-   **libpcap** --- live packet capture
-   **Arch Linux** --- initial development platform

Useful references:

-   Go: https://go.dev/
-   Fyne: https://fyne.io/
-   gopacket: https://github.com/google/gopacket
-   libpcap: https://www.tcpdump.org/

## Installation --- Arch Linux

Update the system and install the core dependencies:

``` bash
sudo pacman -Syu
sudo pacman -S --needed go gcc pkgconf libpcap
```

Check that they are available:

``` bash
go version
gcc --version
pkg-config --modversion libpcap
```

Create the project:

``` bash
mkdir -p ~/Projects/go-packet-explorer
cd ~/Projects/go-packet-explorer
go mod init go-packet-explorer
```

Add the Go libraries:

``` bash
go get fyne.io/fyne/v2
go get github.com/google/gopacket
go mod tidy
```

Fyne's Linux desktop build may require additional system graphics or
windowing development libraries. If the build reports a missing native
dependency, install the Arch package that provides the missing library.

## Folder structure

Initial prototype:

``` text
go-packet-explorer/
├── go.mod
├── go.sum
├── main.go
└── README.md
```

Suggested structure as the project grows:

``` text
go-packet-explorer/
├── go.mod
├── go.sum
├── main.go
├── internal/
│   ├── capture/
│   │   ├── capture.go
│   │   └── capture_test.go
│   ├── packet/
│   │   ├── decode.go
│   │   └── decode_test.go
│   └── ui/
│       ├── app.go
│       └── packet_details.go
├── testdata/
│   └── README.md
└── README.md
```

Keep capture, packet decoding, and UI responsibilities separate as the
codebase grows.

------------------------------------------------------------------------

# Development roadmap

## Phase 1 --- Live packet viewer

**Objective:** Capture live packets and display them in a desktop
window.

### Features

-   [ ] List available network interfaces.
-   [ ] Select an interface.
-   [ ] Start and stop capture.
-   [ ] Display packets in a live table.
-   [ ] Show timestamp, protocol, source, destination, and length.
-   [ ] Select a packet to view basic decoded details.
-   [ ] Keep the GUI responsive during capture.
-   [ ] Handle capture errors visibly.

### Implementation concepts

-   `pcap.OpenLive()` opens a capture handle.
-   `gopacket.NewPacketSource()` provides decoded packets.
-   A goroutine reads packets independently of the UI.
-   Fyne UI updates must be scheduled safely on the GUI thread.
-   A bounded packet history prevents the displayed list from growing
    forever.

### Build and run

From the project directory:

``` bash
go mod tidy
go build -o packet-explorer .
./packet-explorer
```

Live capture typically requires elevated privileges or configured
capture permissions. For an initial local test only, you may run:

``` bash
sudo ./packet-explorer
```

Do not make running the entire GUI as root the permanent design. Later,
use narrowly scoped capture permissions or a separate privileged capture
helper.

### Test

Inspect interfaces:

``` bash
ip -br link
```

Choose `lo` to observe local loopback traffic, then generate traffic in
another terminal:

``` bash
ping -c 4 127.0.0.1
```

For DNS traffic, use an appropriate physical or wireless interface:

``` bash
dig example.com
```

If `dig` is not installed on Arch Linux:

``` bash
sudo pacman -S --needed bind
```

### Phase 1 acceptance criteria

-   [ ] Application opens.
-   [ ] Interfaces are listed.
-   [ ] Capture starts and packets appear.
-   [ ] Selecting a packet shows its details.
-   [ ] Capture can be stopped.
-   [ ] GUI remains responsive during ordinary test traffic.
-   [ ] Errors are shown rather than silently ignored.

### Known prototype limitations

The first prototype may need improvements to handle non-Ethernet link
types, capture errors, high packet rates, and shutdown races. Validate
the decoder against the selected interface's link type. Promiscuous mode
does not make switched-network traffic from other hosts automatically
visible.

------------------------------------------------------------------------

## Phase 2 --- Packet inspection and filters

**Objective:** Make it practical to find and inspect specific traffic.

### Features

-   [ ] Search or filter the displayed packet list.
-   [ ] Add BPF capture filters, such as `tcp`, `udp`, or `port 53`.
-   [ ] Show Ethernet, IP, TCP, and UDP fields in a details tree.
-   [ ] Add a hexadecimal and ASCII payload view.
-   [ ] Add sortable columns.
-   [ ] Display capture errors and dropped-packet statistics when
    available.

### Learning topics

-   BPF syntax and the difference between capture filters and display
    filters.
-   Ethernet frames, IP packets, TCP segments, and UDP datagrams.
-   Ports, flags, packet length, and timestamps.
-   Why a capture point affects which packets are visible.

### Acceptance criteria

-   [ ] Applying a capture filter changes what is captured.
-   [ ] Display filtering does not require restarting capture.
-   [ ] Packet details match the decoded packet.
-   [ ] Large captures remain usable.

------------------------------------------------------------------------

## Phase 3 --- Visual learning and flow tracking

**Objective:** Explain how packets relate to each other.

### Features

-   [ ] Track conversations using protocol and endpoint tuples.
-   [ ] Visualize TCP SYN → SYN-ACK → ACK.
-   [ ] Show packets in a selected conversation.
-   [ ] Explain common TCP flags in plain language.
-   [ ] Add protocol summaries and traffic-rate charts.
-   [ ] Clearly distinguish observed facts from inferred explanations.

### Learning topics

-   TCP connection establishment and teardown.
-   Client/server roles and ephemeral ports.
-   Retransmissions, resets, and timeouts.
-   What a packet capture can and cannot prove.

### Acceptance criteria

-   [ ] A TCP conversation can be selected and inspected.
-   [ ] The handshake visualization reflects observed packets.
-   [ ] Missing packets are not falsely presented as proof that an event
    did not happen.
-   [ ] Explanations are grounded in decoded fields.

------------------------------------------------------------------------

## Phase 4 --- PCAP files and reliability

**Objective:** Make the application useful for repeatable analysis.

### Features

-   [ ] Open saved PCAP files.
-   [ ] Export captures to PCAP.
-   [ ] Support PCAPNG where the chosen libraries permit it.
-   [ ] Add pause/resume or snapshot behavior.
-   [ ] Batch GUI updates and use bounded queues.
-   [ ] Track captured, displayed, and dropped packets separately.
-   [ ] Add unit tests for packet decoding and filtering.
-   [ ] Handle repeated start/stop and window closure safely.
-   [ ] Document permissions, privacy, and safe capture practices.

### Acceptance criteria

-   [ ] Saved captures can be reopened and inspected.
-   [ ] Memory use remains bounded during long captures.
-   [ ] Shutdown closes capture resources cleanly.
-   [ ] Core decoding logic has tests.
-   [ ] The app reports limitations and errors clearly.

------------------------------------------------------------------------

## Suggested learning workflow

For every new feature:

1.  **Understand:** Write down the problem the feature solves.
2.  **Diagram:** Draw the packet path or component interaction.
3.  **Observe:** Capture or inspect a small example.
4.  **Implement:** Build the smallest working version.
5.  **Verify:** Compare the app's output with known packet fields or a
    trusted capture tool.
6.  **Explain:** Describe what the feature shows---and what it cannot
    conclude.

Keep each phase small. Finish and test the current phase before adding
the next one.

## Safety and privacy

Only capture traffic on systems and networks you own or are explicitly
authorized to inspect. Packet captures can contain sensitive
information. Minimize collection, protect saved capture files, and avoid
capturing payloads unless they are necessary for the task.

## Current milestone

**Phase 1: Live packet viewer**

Next: stabilize capture lifecycle and link-layer handling, then extract
the capture and decoding code into separate packages before adding Phase
2 features.
# go-packet
