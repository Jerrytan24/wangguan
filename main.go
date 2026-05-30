package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"github.com/xuri/excelize/v2"
)

//go:embed static/*
var staticFiles embed.FS

type Device struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	IP              string `json:"ip"`
	Status          string `json:"status"`
	Type            string `json:"type"`
	Location        string `json:"location"`
	LastSeen        string `json:"lastSeen"`
	ReadOnlyCommunity string `json:"readOnlyCommunity"`
	SNMPPort        int    `json:"snmpPort"`
	DeviceGroup     string `json:"deviceGroup"`
	LoginPassword   string `json:"loginPassword"`
	CollectInterval int    `json:"collectInterval"`
	SNMPTimeout     int    `json:"snmpTimeout"`
	SNMPRetry       int    `json:"snmpRetry"`
}

type DeviceGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	Remark      string `json:"remark"`
	DeviceCount int    `json:"deviceCount"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Role     string `json:"role"`
}

type SystemConfig struct {
	InfluxDBURL      string `json:"influxDBURL"`
	InfluxDBToken    string `json:"influxDBToken"`
	InfluxDBOrg      string `json:"influxDBOrg"`
	InfluxDBBucket   string `json:"influxDBBucket"`
	InfluxDBRetention string `json:"influxDBRetention"`
	ServerListenAddr string `json:"serverListenAddr"`
	ServerPort       int    `json:"serverPort"`
	ServerTimeout    int    `json:"serverTimeout"`
	AllowExternalAccess bool `json:"allowExternalAccess"`
	WebhookURL       string `json:"webhookURL"`
	EnableWebhook    bool `json:"enableWebhook"`
}

type Alert struct {
	ID       string `json:"id"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	DeviceID string `json:"deviceId"`
	DeviceIP string `json:"deviceIp"`
	Time     string `json:"time"`
}

type Position struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type NetworkNode struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	IP          string   `json:"ip"`
	Type        string   `json:"type"`
	Position    Position `json:"position"`
	Connections []string `json:"connections"`
}

type DashboardData struct {
	TotalDevices     int     `json:"totalDevices"`
	ActiveDevices    int     `json:"activeDevices"`
	AlertCount       int     `json:"alertCount"`
	NetworkTraffic   float64 `json:"networkTraffic"`
	CpuUsage         float64 `json:"cpuUsage"`
	MemoryUsage      float64 `json:"memoryUsage"`
	NetworkLatency   float64 `json:"networkLatency"`
	PacketLoss       float64 `json:"packetLoss"`
}

type AddDeviceRequest struct {
	Name              string `json:"name"`
	IP                string `json:"ip"`
	Type              string `json:"type"`
	ReadOnlyCommunity string `json:"readOnlyCommunity"`
	SNMPPort          int    `json:"snmpPort"`
	DeviceGroup       string `json:"deviceGroup"`
	LoginPassword     string `json:"loginPassword"`
	CollectInterval   int    `json:"collectInterval"`
	SNMPTimeout       int    `json:"snmpTimeout"`
	SNMPRetry         int    `json:"snmpRetry"`
	Location          string `json:"location"`
}

type OIDMetric struct {
	ID          string `json:"id"`
	DeviceID    string `json:"deviceId"`
	Name        string `json:"name"`
	OID         string `json:"oid"`
	Description string `json:"description"`
	Unit        string `json:"unit"`
	DataType    string `json:"dataType"`
	Enabled     bool   `json:"enabled"`
}

type TestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

type WebShellConfig struct {
	DeviceID string `json:"deviceId"`
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	db     *sql.DB
	dbMu   sync.Mutex
	nextID int = 1000
)

func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "./netman.db")
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	if err = createTables(); err != nil {
		return err
	}

	if err = initDefaultData(); err != nil {
		return err
	}

	return nil
}

func createTables() error {
	sqlStatements := []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			ip TEXT NOT NULL,
			status TEXT DEFAULT 'online',
			type TEXT NOT NULL,
			location TEXT,
			last_seen TEXT,
			read_only_community TEXT,
			snmp_port INTEGER DEFAULT 161,
			device_group TEXT,
			login_password TEXT,
			collect_interval INTEGER DEFAULT 3,
			snmp_timeout INTEGER DEFAULT 3,
			snmp_retry INTEGER DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS device_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			icon TEXT,
			remark TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			nickname TEXT,
			role TEXT DEFAULT 'admin',
			password TEXT DEFAULT 'admin'
		)`,
		`CREATE TABLE IF NOT EXISTS system_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			influx_db_url TEXT,
			influx_db_token TEXT,
			influx_db_org TEXT,
			influx_db_bucket TEXT,
			influx_db_retention TEXT,
			server_listen_addr TEXT DEFAULT '0.0.0.0',
			server_port INTEGER DEFAULT 8080,
			server_timeout INTEGER DEFAULT 180,
			allow_external_access BOOLEAN DEFAULT 1,
			webhook_url TEXT,
			enable_webhook BOOLEAN DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			level TEXT NOT NULL,
			message TEXT NOT NULL,
			device_id TEXT,
			device_ip TEXT,
			time TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS oid_metrics (
			id TEXT PRIMARY KEY,
			device_id TEXT NOT NULL,
			name TEXT NOT NULL,
			oid TEXT NOT NULL,
			description TEXT,
			unit TEXT,
			data_type TEXT,
			enabled BOOLEAN DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS network_nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			ip TEXT,
			type TEXT,
			position_x INTEGER,
			position_y INTEGER,
			connections TEXT
		)`,
	}

	for _, stmt := range sqlStatements {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

func initDefaultData() error {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM device_groups").Scan(&count)
	if count == 0 {
		groups := []DeviceGroup{
			{"1", "路由器", "fa-router", "核心/汇聚路由设备", 0},
			{"2", "交换机", "fa-sitemap", "接入/汇聚/核心交换机", 0},
			{"3", "防火墙", "fa-shield-alt", "安全防护设备", 0},
			{"4", "无线AP", "fa-wifi", "无线接入点", 0},
			{"5", "服务器", "fa-server", "服务器设备", 0},
			{"6", "其他", "fa-hdd", "其他网络设备", 0},
		}
		for _, g := range groups {
			_, err := db.Exec("INSERT INTO device_groups (id, name, icon, remark) VALUES (?, ?, ?, ?)", g.ID, g.Name, g.Icon, g.Remark)
			if err != nil {
				return err
			}
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		_, err := db.Exec("INSERT INTO users (id, username, nickname, role, password) VALUES (?, ?, ?, ?, ?)", "1", "admin", "系统管理员", "admin", "admin")
		if err != nil {
			return err
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM system_config").Scan(&count)
	if count == 0 {
		_, err := db.Exec(`INSERT INTO system_config (influx_db_url, influx_db_token, influx_db_org, influx_db_bucket, influx_db_retention, server_listen_addr, server_port, server_timeout, allow_external_access, webhook_url, enable_webhook) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"http://localhost:8086", "", "influxdb", "influxdb", "30天", "0.0.0.0", 8080, 180, true, "", false)
		if err != nil {
			return err
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&count)
	if count == 0 {
		devices := []Device{
			{"1", "核心交换机", "192.168.1.1", "online", "switch", "机房A-1", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "核心设备", "", 3, 3, 1},
			{"2", "路由器-主", "192.168.1.2", "online", "router", "机房A-2", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "核心设备", "", 3, 3, 1},
			{"3", "防火墙", "192.168.1.3", "online", "firewall", "机房A-3", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "安全设备", "", 3, 3, 1},
			{"4", "负载均衡器", "192.168.1.4", "online", "switch", "机房A-4", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "核心设备", "", 3, 3, 1},
			{"5", "接入交换机-1", "192.168.1.10", "online", "switch", "楼层1", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "接入设备", "", 3, 3, 1},
			{"6", "接入交换机-2", "192.168.1.11", "warning", "switch", "楼层2", time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04:05"), "public", 161, "接入设备", "", 3, 3, 1},
			{"7", "无线AP-1", "192.168.1.20", "online", "ap", "办公室A", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "无线设备", "", 3, 3, 1},
			{"8", "服务器-Web", "192.168.1.100", "online", "server", "机房B-1", time.Now().Format("2006-01-02 15:04:05"), "public", 161, "服务器", "", 3, 3, 1},
		}
		for _, d := range devices {
			_, err := db.Exec(`INSERT INTO devices (id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				d.ID, d.Name, d.IP, d.Status, d.Type, d.Location, d.LastSeen, d.ReadOnlyCommunity, d.SNMPPort, d.DeviceGroup, d.LoginPassword, d.CollectInterval, d.SNMPTimeout, d.SNMPRetry)
			if err != nil {
				return err
			}
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	if count == 0 {
		alerts := []Alert{
			{"1", "critical", "核心交换机CPU使用率超过90%", "1", "192.168.1.1", time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04:05")},
			{"2", "warning", "接入交换机-2响应延迟", "6", "192.168.1.11", time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04:05")},
			{"3", "info", "设备定期维护提醒", "2", "192.168.1.2", time.Now().Add(-30 * time.Minute).Format("2006-01-02 15:04:05")},
		}
		for _, a := range alerts {
			_, err := db.Exec("INSERT INTO alerts (id, level, message, device_id, device_ip, time) VALUES (?, ?, ?, ?, ?, ?)", a.ID, a.Level, a.Message, a.DeviceID, a.DeviceIP, a.Time)
			if err != nil {
				return err
			}
		}
	}

	db.QueryRow("SELECT COUNT(*) FROM network_nodes").Scan(&count)
	if count == 0 {
		nodes := []NetworkNode{
			{"1", "核心交换机", "192.168.1.1", "switch", Position{400, 100}, []string{"2", "3", "4"}},
			{"2", "路由器", "192.168.1.2", "router", Position{200, 250}, []string{"1", "5", "6"}},
			{"3", "防火墙", "192.168.1.3", "firewall", Position{400, 250}, []string{"1", "8"}},
			{"4", "负载均衡器", "192.168.1.4", "switch", Position{600, 250}, []string{"1", "7"}},
			{"5", "接入交换机-1", "192.168.1.10", "switch", Position{100, 400}, []string{"2"}},
			{"6", "接入交换机-2", "192.168.1.11", "switch", Position{300, 400}, []string{"2"}},
			{"7", "无线AP", "192.168.1.20", "ap", Position{500, 400}, []string{"4"}},
			{"8", "服务器", "192.168.1.100", "server", Position{700, 400}, []string{"3"}},
		}
		for _, n := range nodes {
			connStr, _ := json.Marshal(n.Connections)
			_, err := db.Exec("INSERT INTO network_nodes (id, name, ip, type, position_x, position_y, connections) VALUES (?, ?, ?, ?, ?, ?, ?)", n.ID, n.Name, n.IP, n.Type, n.Position.X, n.Position.Y, string(connStr))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getNextID() int {
	dbMu.Lock()
	nextID++
	id := nextID
	dbMu.Unlock()
	return id
}

func main() {
	if err := initDB(); err != nil {
		log.Fatal("Failed to init DB:", err)
	}
	defer db.Close()

	fs, _ := fs.Sub(staticFiles, "static")
	http.Handle("/", http.FileServer(http.FS(fs)))

	http.HandleFunc("/api/devices", devicesHandler)
	http.HandleFunc("/api/devices/batch", batchAddDevicesHandler)
	http.HandleFunc("/api/devices/import/excel", importExcelHandler)
	http.HandleFunc("/api/devices/template/download", downloadTemplateHandler)
	http.HandleFunc("/api/devices/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/webshell") {
			webShellHandler(w, r)
		} else if strings.Contains(r.URL.Path, "/test") {
			testDeviceHandler(w, r)
		} else if strings.Contains(r.URL.Path, "/oid") {
			deviceOIDHandler(w, r)
		} else if strings.Contains(r.URL.Path, "/interfaces") {
			deviceInterfacesHandler(w, r)
		} else {
			deviceHandler(w, r)
		}
	})

	http.HandleFunc("/api/device-groups", deviceGroupsHandler)
	http.HandleFunc("/api/device-groups/", deviceGroupHandler)

	http.HandleFunc("/api/users", usersHandler)
	http.HandleFunc("/api/users/", userHandler)

	http.HandleFunc("/api/system-config/test-influxdb", testInfluxDBConnectionHandler)
	http.HandleFunc("/api/system-config", systemConfigHandler)

	http.HandleFunc("/api/oid/metrics", oidMetricsHandler)
	http.HandleFunc("/api/alerts", getAlerts)
	http.HandleFunc("/api/network", getNetwork)
	http.HandleFunc("/api/dashboard", getDashboard)
	http.HandleFunc("/api/packets", getPackets)
	http.HandleFunc("/api/login", loginHandler)

	fmt.Println("网络管理系统启动中...")
	fmt.Println("服务地址: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry FROM devices")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		devices := []Device{}
		for rows.Next() {
			var d Device
			rows.Scan(&d.ID, &d.Name, &d.IP, &d.Status, &d.Type, &d.Location, &d.LastSeen, &d.ReadOnlyCommunity, &d.SNMPPort, &d.DeviceGroup, &d.LoginPassword, &d.CollectInterval, &d.SNMPTimeout, &d.SNMPRetry)
			devices = append(devices, d)
		}
		json.NewEncoder(w).Encode(devices)
	} else if r.Method == http.MethodPost {
		var req AddDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		deviceID := strconv.Itoa(getNextID())
		device := Device{
			ID:              deviceID,
			Name:            req.Name,
			IP:              req.IP,
			Type:            req.Type,
			Status:          "online",
			Location:        req.Location,
			LastSeen:        time.Now().Format("2006-01-02 15:04:05"),
			ReadOnlyCommunity: req.ReadOnlyCommunity,
			SNMPPort:        req.SNMPPort,
			DeviceGroup:     req.DeviceGroup,
			LoginPassword:   req.LoginPassword,
			CollectInterval: req.CollectInterval,
			SNMPTimeout:     req.SNMPTimeout,
			SNMPRetry:       req.SNMPRetry,
		}

		_, err := db.Exec(`INSERT INTO devices (id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, device.Name, device.IP, device.Status, device.Type, device.Location, device.LastSeen, device.ReadOnlyCommunity, device.SNMPPort, device.DeviceGroup, device.LoginPassword, device.CollectInterval, device.SNMPTimeout, device.SNMPRetry)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"device":  device,
		})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func deviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	deviceID := r.URL.Path[len("/api/devices/"):]
	if deviceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Device ID is required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		var d Device
		err := db.QueryRow("SELECT id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry FROM devices WHERE id = ?", deviceID).Scan(
			&d.ID, &d.Name, &d.IP, &d.Status, &d.Type, &d.Location, &d.LastSeen, &d.ReadOnlyCommunity, &d.SNMPPort, &d.DeviceGroup, &d.LoginPassword, &d.CollectInterval, &d.SNMPTimeout, &d.SNMPRetry)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Device not found"})
			return
		}
		json.NewEncoder(w).Encode(d)

	case http.MethodDelete:
		_, err := db.Exec("DELETE FROM devices WHERE id = ?", deviceID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	case http.MethodPut:
		var req Device
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		_, err := db.Exec(`UPDATE devices SET name = ?, ip = ?, status = ?, type = ?, location = ?, last_seen = ?, read_only_community = ?, snmp_port = ?, device_group = ?, login_password = ?, collect_interval = ?, snmp_timeout = ?, snmp_retry = ? WHERE id = ?`,
			req.Name, req.IP, req.Status, req.Type, req.Location, req.LastSeen, req.ReadOnlyCommunity, req.SNMPPort, req.DeviceGroup, req.LoginPassword, req.CollectInterval, req.SNMPTimeout, req.SNMPRetry, deviceID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"device":  req,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func batchAddDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var req []AddDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	addedDevices := []Device{}
	for _, devReq := range req {
		deviceID := strconv.Itoa(getNextID())
		device := Device{
			ID:              deviceID,
			Name:            devReq.Name,
			IP:              devReq.IP,
			Type:            devReq.Type,
			Status:          "online",
			Location:        devReq.Location,
			LastSeen:        time.Now().Format("2006-01-02 15:04:05"),
			ReadOnlyCommunity: devReq.ReadOnlyCommunity,
			SNMPPort:        devReq.SNMPPort,
			DeviceGroup:     devReq.DeviceGroup,
			LoginPassword:   devReq.LoginPassword,
			CollectInterval: devReq.CollectInterval,
			SNMPTimeout:     devReq.SNMPTimeout,
			SNMPRetry:       devReq.SNMPRetry,
		}

		_, err := db.Exec(`INSERT INTO devices (id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, device.Name, device.IP, device.Status, device.Type, device.Location, device.LastSeen, device.ReadOnlyCommunity, device.SNMPPort, device.DeviceGroup, device.LoginPassword, device.CollectInterval, device.SNMPTimeout, device.SNMPRetry)
		if err != nil {
			continue
		}
		addedDevices = append(addedDevices, device)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(addedDevices),
		"devices": addedDevices,
	})
}

func downloadTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", "attachment; filename=device_template.xlsx")

	f := excelize.NewFile()
	f.SetCellValue("Sheet1", "A1", "设备名称")
	f.SetCellValue("Sheet1", "B1", "IP地址")
	f.SetCellValue("Sheet1", "C1", "设备类型")
	f.SetCellValue("Sheet1", "D1", "位置")
	f.SetCellValue("Sheet1", "E1", "只读Community")
	f.SetCellValue("Sheet1", "F1", "SNMP端口")
	f.SetCellValue("Sheet1", "G1", "设备分组")
	f.SetCellValue("Sheet1", "H1", "登录口令")
	f.SetCellValue("Sheet1", "I1", "采集间隔(分钟)")
	f.SetCellValue("Sheet1", "J1", "SNMP超时(秒)")
	f.SetCellValue("Sheet1", "K1", "SNMP重试次数")

	f.SetCellValue("Sheet1", "A2", "核心交换机-1")
	f.SetCellValue("Sheet1", "B2", "192.168.1.1")
	f.SetCellValue("Sheet1", "C2", "switch")
	f.SetCellValue("Sheet1", "D2", "机房A-1")
	f.SetCellValue("Sheet1", "E2", "public")
	f.SetCellValue("Sheet1", "F2", 161)
	f.SetCellValue("Sheet1", "G2", "核心设备")
	f.SetCellValue("Sheet1", "H2", "admin")
	f.SetCellValue("Sheet1", "I2", 3)
	f.SetCellValue("Sheet1", "J2", 3)
	f.SetCellValue("Sheet1", "K2", 1)

	f.SetCellValue("Sheet1", "A3", "路由器-主")
	f.SetCellValue("Sheet1", "B3", "192.168.1.2")
	f.SetCellValue("Sheet1", "C3", "router")
	f.SetCellValue("Sheet1", "D3", "机房A-2")
	f.SetCellValue("Sheet1", "E3", "public")
	f.SetCellValue("Sheet1", "F3", 161)
	f.SetCellValue("Sheet1", "G3", "核心设备")
	f.SetCellValue("Sheet1", "H3", "")
	f.SetCellValue("Sheet1", "I3", 5)
	f.SetCellValue("Sheet1", "J3", 5)
	f.SetCellValue("Sheet1", "K3", 2)

	f.Write(w)
}

func importExcelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "File too large"})
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	f, err := excelize.OpenReader(file)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Excel file"})
		return
	}

	rows, err := f.GetRows("Sheet1")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read rows"})
		return
	}

	if len(rows) < 2 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No data found"})
		return
	}

	addedDevices := []Device{}
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		if len(row) < 2 || row[0] == "" || row[1] == "" {
			continue
		}

		snmpPort := 161
		if len(row) > 5 && row[5] != "" {
			snmpPort, _ = strconv.Atoi(row[5])
		}

		collectInterval := 3
		if len(row) > 8 && row[8] != "" {
			collectInterval, _ = strconv.Atoi(row[8])
		}

		snmpTimeout := 3
		if len(row) > 9 && row[9] != "" {
			snmpTimeout, _ = strconv.Atoi(row[9])
		}

		snmpRetry := 1
		if len(row) > 10 && row[10] != "" {
			snmpRetry, _ = strconv.Atoi(row[10])
		}

		deviceID := strconv.Itoa(getNextID())
		device := Device{
			ID:              deviceID,
			Name:            row[0],
			IP:              row[1],
			Type:            row[2],
			Location:        row[3],
			ReadOnlyCommunity: row[4],
			SNMPPort:        snmpPort,
			DeviceGroup:     row[6],
			LoginPassword:   row[7],
			CollectInterval: collectInterval,
			SNMPTimeout:     snmpTimeout,
			SNMPRetry:       snmpRetry,
			Status:          "online",
			LastSeen:        time.Now().Format("2006-01-02 15:04:05"),
		}

		_, err := db.Exec(`INSERT INTO devices (id, name, ip, status, type, location, last_seen, read_only_community, snmp_port, device_group, login_password, collect_interval, snmp_timeout, snmp_retry) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, device.Name, device.IP, device.Status, device.Type, device.Location, device.LastSeen, device.ReadOnlyCommunity, device.SNMPPort, device.DeviceGroup, device.LoginPassword, device.CollectInterval, device.SNMPTimeout, device.SNMPRetry)
		if err != nil {
			continue
		}
		addedDevices = append(addedDevices, device)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(addedDevices),
		"devices": addedDevices,
	})
}

func testDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var req struct {
		DeviceID string `json:"deviceId"`
		OID      string `json:"oid"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	var d Device
	db.QueryRow("SELECT id, name, ip FROM devices WHERE id = ?", req.DeviceID).Scan(&d.ID, &d.Name, &d.IP)
	if d.ID == "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Device not found"})
		return
	}

	testOID := req.OID
	if testOID == "" {
		testOID = "1.3.6.1.2.1.1.1.0"
	}

	time.Sleep(500 * time.Millisecond)

	result := TestResult{
		Success: true,
		Message: "SNMP采集测试成功",
		Data:    fmt.Sprintf("设备: %s (%s)\nOID: %s\n返回值: 设备描述信息 - 测试数据", d.Name, d.IP, testOID),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func webShellHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	deviceID := strings.Split(r.URL.Path, "/")[3]

	var d Device
	db.QueryRow("SELECT id, name, ip, login_password FROM devices WHERE id = ?", deviceID).Scan(&d.ID, &d.Name, &d.IP, &d.LoginPassword)
	if d.ID == "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Device not found"})
		return
	}

	config := WebShellConfig{
		DeviceID: d.ID,
		Protocol: "telnet",
		IP:       d.IP,
		Port:     23,
		Username: "admin",
		Password: d.LoginPassword,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config":  config,
	})
}

func deviceOIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid URL"})
		return
	}
	deviceID := parts[3]

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query("SELECT id, device_id, name, oid, description, unit, data_type, enabled FROM oid_metrics WHERE device_id = ?", deviceID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		metrics := []OIDMetric{}
		for rows.Next() {
			var m OIDMetric
			rows.Scan(&m.ID, &m.DeviceID, &m.Name, &m.OID, &m.Description, &m.Unit, &m.DataType, &m.Enabled)
			metrics = append(metrics, m)
		}
		json.NewEncoder(w).Encode(metrics)

	case http.MethodPost:
		var metric OIDMetric
		if err := json.NewDecoder(r.Body).Decode(&metric); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		metric.ID = strconv.Itoa(getNextID())
		metric.DeviceID = deviceID
		metric.Enabled = true

		_, err := db.Exec("INSERT INTO oid_metrics (id, device_id, name, oid, description, unit, data_type, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			metric.ID, metric.DeviceID, metric.Name, metric.OID, metric.Description, metric.Unit, metric.DataType, metric.Enabled)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"metric":  metric,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func oidMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query("SELECT id, device_id, name, oid, description, unit, data_type, enabled FROM oid_metrics")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		metrics := []OIDMetric{}
		for rows.Next() {
			var m OIDMetric
			rows.Scan(&m.ID, &m.DeviceID, &m.Name, &m.OID, &m.Description, &m.Unit, &m.DataType, &m.Enabled)
			metrics = append(metrics, m)
		}
		json.NewEncoder(w).Encode(metrics)

	case http.MethodDelete:
		metricID := r.URL.Query().Get("id")
		if metricID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metric ID is required"})
			return
		}

		_, err := db.Exec("DELETE FROM oid_metrics WHERE id = ?", metricID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func deviceGroupsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, icon, remark FROM device_groups")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		groups := []DeviceGroup{}
		for rows.Next() {
			var g DeviceGroup
			rows.Scan(&g.ID, &g.Name, &g.Icon, &g.Remark)
			var count int
			db.QueryRow("SELECT COUNT(*) FROM devices WHERE device_group = ?", g.Name).Scan(&count)
			g.DeviceCount = count
			groups = append(groups, g)
		}
		json.NewEncoder(w).Encode(groups)
	} else if r.Method == http.MethodPost {
		var req DeviceGroup
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		req.ID = strconv.Itoa(getNextID())
		_, err := db.Exec("INSERT INTO device_groups (id, name, icon, remark) VALUES (?, ?, ?, ?)", req.ID, req.Name, req.Icon, req.Remark)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"group":   req,
		})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func deviceGroupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	groupID := r.URL.Path[len("/api/device-groups/"):]
	if groupID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Group ID is required"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req DeviceGroup
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		_, err := db.Exec("UPDATE device_groups SET name = ?, icon = ?, remark = ? WHERE id = ?", req.Name, req.Icon, req.Remark, groupID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	case http.MethodDelete:
		_, err := db.Exec("DELETE FROM device_groups WHERE id = ?", groupID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, username, nickname, role FROM users")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := []User{}
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Username, &u.Nickname, &u.Role)
			users = append(users, u)
		}
		json.NewEncoder(w).Encode(users)
	} else if r.Method == http.MethodPost {
		var req User
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		req.ID = strconv.Itoa(getNextID())
		_, err := db.Exec("INSERT INTO users (id, username, nickname, role, password) VALUES (?, ?, ?, ?, 'admin')", req.ID, req.Username, req.Nickname, req.Role)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"user":    req,
		})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	userID := r.URL.Path[len("/api/users/"):]
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "User ID is required"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Nickname string `json:"nickname"`
			Role     string `json:"role"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		if req.Password != "" {
			_, err := db.Exec("UPDATE users SET username = ?, nickname = ?, role = ?, password = ? WHERE id = ?", req.Username, req.Nickname, req.Role, req.Password, userID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		} else {
			_, err := db.Exec("UPDATE users SET username = ?, nickname = ?, role = ? WHERE id = ?", req.Username, req.Nickname, req.Role, userID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	case http.MethodDelete:
		_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func systemConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		var config SystemConfig
		err := db.QueryRow(`SELECT influx_db_url, influx_db_token, influx_db_org, influx_db_bucket, influx_db_retention, server_listen_addr, server_port, server_timeout, allow_external_access, webhook_url, enable_webhook FROM system_config WHERE id = 1`).Scan(
			&config.InfluxDBURL, &config.InfluxDBToken, &config.InfluxDBOrg, &config.InfluxDBBucket, &config.InfluxDBRetention,
			&config.ServerListenAddr, &config.ServerPort, &config.ServerTimeout, &config.AllowExternalAccess,
			&config.WebhookURL, &config.EnableWebhook)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(config)
	} else if r.Method == http.MethodPut {
		var config SystemConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
			return
		}

		_, err := db.Exec(`UPDATE system_config SET influx_db_url = ?, influx_db_token = ?, influx_db_org = ?, influx_db_bucket = ?, influx_db_retention = ?, server_listen_addr = ?, server_port = ?, server_timeout = ?, allow_external_access = ?, webhook_url = ?, enable_webhook = ? WHERE id = 1`,
			config.InfluxDBURL, config.InfluxDBToken, config.InfluxDBOrg, config.InfluxDBBucket, config.InfluxDBRetention,
			config.ServerListenAddr, config.ServerPort, config.ServerTimeout, config.AllowExternalAccess,
			config.WebhookURL, config.EnableWebhook)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func testInfluxDBConnectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var config struct {
		InfluxDBURL   string `json:"influxDBURL"`
		InfluxDBToken string `json:"influxDBToken"`
		InfluxDBOrg   string `json:"influxDBOrg"`
		InfluxDBBucket string `json:"influxDBBucket"`
	}

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", config.InfluxDBURL+"/api/v2/orgs", nil)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid URL",
		})
		return
	}

	req.Header.Set("Authorization", "Token "+config.InfluxDBToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Connection successful",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("HTTP %d", resp.StatusCode),
		})
	}
}

func getAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("SELECT id, level, message, device_id, device_ip, time FROM alerts")
	if err != nil {
		json.NewEncoder(w).Encode([]Alert{})
		return
	}
	defer rows.Close()

	alerts := []Alert{}
	for rows.Next() {
		var a Alert
		rows.Scan(&a.ID, &a.Level, &a.Message, &a.DeviceID, &a.DeviceIP, &a.Time)
		alerts = append(alerts, a)
	}
	json.NewEncoder(w).Encode(alerts)
}

func getNetwork(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := db.Query("SELECT id, name, ip, type, position_x, position_y, connections FROM network_nodes")
	if err != nil {
		json.NewEncoder(w).Encode([]NetworkNode{})
		return
	}
	defer rows.Close()

	nodes := []NetworkNode{}
	for rows.Next() {
		var n NetworkNode
		var connStr string
		rows.Scan(&n.ID, &n.Name, &n.IP, &n.Type, &n.Position.X, &n.Position.Y, &connStr)
		json.Unmarshal([]byte(connStr), &n.Connections)
		nodes = append(nodes, n)
	}
	json.NewEncoder(w).Encode(nodes)
}

func getDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var total, active, alertCount int
	db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM devices WHERE status = 'online'").Scan(&active)
	db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount)

	data := DashboardData{
		TotalDevices:   total,
		ActiveDevices:  active,
		AlertCount:     alertCount,
		NetworkTraffic: 85.6,
		CpuUsage:       72.3,
		MemoryUsage:    68.5,
		NetworkLatency: 12.4,
		PacketLoss:     0.1,
	}
	json.NewEncoder(w).Encode(data)
}

func getPackets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	packetData := []struct {
		Time  string  `json:"time"`
		Bytes float64 `json:"bytes"`
	}{
		{"00:00", 12500}, {"01:00", 8900}, {"02:00", 6200}, {"03:00", 5100},
		{"04:00", 4800}, {"05:00", 7200}, {"06:00", 15600}, {"07:00", 28900},
		{"08:00", 45200}, {"09:00", 58900}, {"10:00", 62100}, {"11:00", 55600},
		{"12:00", 48900}, {"13:00", 51200}, {"14:00", 59800}, {"15:00", 65200},
		{"16:00", 61800}, {"17:00", 54300}, {"18:00", 42100}, {"19:00", 35600},
		{"20:00", 28900}, {"21:00", 22300}, {"22:00", 18500}, {"23:00", 14200},
	}
	json.NewEncoder(w).Encode(packetData)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"success": "true", "token": "mock-token"}
	json.NewEncoder(w).Encode(response)
}

func deviceInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid URL"})
		return
	}
	deviceID := parts[3]

	var d Device
	err := db.QueryRow("SELECT id, name, ip, read_only_community, snmp_port, collect_interval, snmp_timeout, snmp_retry FROM devices WHERE id = ?", deviceID).Scan(
		&d.ID, &d.Name, &d.IP, &d.ReadOnlyCommunity, &d.SNMPPort, &d.CollectInterval, &d.SNMPTimeout, &d.SNMPRetry)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Device not found"})
		return
	}

	interfaces, err := GetDeviceInterfaces(d.IP, d.ReadOnlyCommunity, d.SNMPTimeout, d.SNMPRetry, d.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(interfaces)
}

