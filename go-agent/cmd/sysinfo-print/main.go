package main

import (
	"fmt"
	"os"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

func main() {
	fmt.Println("hostname:", sysinfo.Hostname())
	fmt.Println("os:", sysinfo.OsDescription())
	fmt.Println("system_info:", sysinfo.SystemInfo())
	fmt.Println("domain:", sysinfo.Domain())
	fmt.Println("ip:", sysinfo.LocalIPv4())

	base := config.DataBaseDir()
	fmt.Println("base:", base)

	cfg, err := config.Load(base)
	if err != nil {
		fmt.Println("config load:", err)
		os.Exit(1)
	}
	client := api.New(cfg)
	resp, raw, err := client.DataInfo()
	if err != nil {
		fmt.Println("dataInfo err:", err)
		os.Exit(1)
	}
	fmt.Println("dataInfo status:", resp.StatusCode)
	fmt.Println("dataInfo body:", string(raw))

	st := history.New(base)
	evs, err := st.ReadRecent(1, 40)
	if err != nil {
		fmt.Println("history:", err)
		return
	}
	fmt.Println("--- recent history ---")
	for _, e := range evs {
		fmt.Printf("%s [%s] %s meta=%v\n", e.TimeRFC3339, e.Kind, e.Message, e.Meta)
	}
}
