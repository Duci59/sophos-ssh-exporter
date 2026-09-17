# sophos-ssh-exporter

Prometheus exporter cho **Sophos Firewall (SFOS / XGS series)**, lấy metric
bằng cách SSH vào CLI của thiết bị, điều hướng vào **Device Console** và
chạy các lệnh `system diagnostics ...` — thay vì phụ thuộc vào SNMP hay
API quản lý (XML API / Sophos Central API), vốn không expose đầy đủ các
chỉ số vận hành thời gian thực mà đội ngũ hạ tầng thường cần.

Đã kiểm chứng thực tế trên **SFOS 21.5.0 GA-Build171 / Sophos XGS 4500**.

---

## Giới thiệu

Sophos Firewall không có sẵn Prometheus exporter chính thức. Hai hướng
tiếp cận phổ biến khác đều có giới hạn:

- **SNMP**: đầy đủ counter hiệu năng hệ thống hơn, nhưng phải bật SNMP
  trên thiết bị và phụ thuộc MIB do Sophos cung cấp — không phải lúc nào
  cũng có đúng chỉ số bạn cần.
- **XML API** (`webconsole/APIController`): mạnh về quản lý object cấu
  hình (IPHost, Rule, User...) và vài thống kê usage theo object, nhưng
  **không** expose các lệnh chẩn đoán hệ thống (`system diagnostics ...`)
  mà admin vẫn dùng hằng ngày qua CLI.

`sophos-ssh-exporter` giải quyết khoảng trống đó: nếu một chỉ số **xem
được bằng lệnh CLI** trong Device Console, nó **lấy được và đưa vào
Prometheus** — không cần Sophos hỗ trợ thêm ở API hay SNMP.

## Mục đích

- Đưa các chỉ số vận hành thời gian thực của Sophos Firewall (session
  count, phiên bản signature AV/IPS...) vào hệ thống giám sát Prometheus /
  Grafana sẵn có, cùng chuẩn với các thiết bị mạng khác (FortiGate,
  MikroTik...).
- Không phụ thuộc vào việc Sophos có bổ sung field đó vào API hay SNMP MIB
  hay không — miễn còn xem được qua CLI là lấy được.
- Dễ mở rộng: thêm 1 metric mới = thêm 1 khai báo lệnh + cách trích giá
  trị, không cần đợi vendor hỗ trợ.

## Tác động / Đặc điểm

- **Poll nền theo chu kỳ** (không SSH ngay lúc Prometheus scrape): mỗi
  thiết bị chạy 1 thread riêng, tự SSH — nếu SSH chậm hoặc timeout không
  ảnh hưởng tới scrape timeout của Prometheus vì `/metrics` luôn trả dữ
  liệu đã cache sẵn.
- **Nhiều thiết bị cùng lúc**: mỗi target 1 thread độc lập, lỗi ở thiết bị
  này không ảnh hưởng thiết bị khác.
- **Tự dọn buffer phiên SSH**: xử lý đúng thứ tự banner/prompt của SFOS
  (đã từng gặp lỗi output bị lệch nhịp giữa các lệnh — xem mục *Ghi chú kỹ
  thuật* bên dưới), lọc mã màu ANSI trước khi trích giá trị.
- **Version string dạng "info metric"** đúng chuẩn Prometheus (giống
  `node_uname_info` của node_exporter): giá trị luôn là `1`, chuỗi version
  thật nằm trong label — kèm tự xoá series cũ khi version đổi để tránh tồn
  đọng time series lỗi thời.
- **Metric tự giám sát**: `sophos_ssh_scrape_success` và
  `sophos_ssh_last_scrape_timestamp_seconds` để biết poller có đang chạy
  tốt không, đặt alert được ngay.

## Metric mặc định

| Metric Prometheus | Tương đương FortiGate | Lệnh CLI | Ý nghĩa |
|---|---|---|---|
| `sophos_sys_ses_count` | `fgSysSesCount` | `system diagnostics utilities connections count` | Số session hiện tại |
| `sophos_sys_ses_rate1` | `fgSysSesRate1` | *(tính từ `sophos_sys_ses_count`)* | Hiệu số session count giữa 2 lần poll liên tiếp |
| `sophos_sys_version_av` | `fgSysVersionAv` | `system diagnostics show version-info` | Phiên bản Sophos AV signature (label `version`) |
| `sophos_sys_version_ips` | `fgSysVersionIps` | `system diagnostics show version-info` | Phiên bản IPS/Application signatures (label `version`) |

Ví dụ output thật:

```
sophos_sys_ses_count{instance="fw1"} 13755
sophos_sys_ses_rate1{instance="fw1"} 65
sophos_sys_version_av{instance="fw1",version="1.0.21546"} 1
sophos_sys_version_ips{instance="fw1",version="18.25.57"} 1
sophos_ssh_scrape_success{instance="fw1"} 1
sophos_ssh_last_scrape_timestamp_seconds{instance="fw1"} 1758099600
```

> `sophos_sys_ses_rate1` cần có "lần poll trước" nên chỉ xuất hiện từ lần
> poll thứ 2 trở đi của mỗi thiết bị.

## Cách hoạt động

```
┌─────────────┐   SSH    ┌──────────────────────┐
│  Firewall 1 │◄─────────┤  poller thread #1     │
└─────────────┘          │  (poll_interval giây) │
                          └──────────┬───────────┘
┌─────────────┐   SSH                │ cập nhật
│  Firewall 2 │◄──── poller thread #2┘  Gauge (registry chung)
└─────────────┘                          │
                                          ▼
                                   GET /metrics ◄──── Prometheus scrape
```

Với mỗi target, mỗi vòng poll:

1. SSH vào thiết bị (`ssh user@host -p port`).
2. Nhập password khi gặp prompt `Password:`.
3. Tại Main Menu, gửi `4` để vào **Device Console**.
4. Đợi prompt `console>` đầu tiên xuất hiện (đồng bộ buffer sau banner).
5. Gửi lần lượt các lệnh cần thiết, mỗi lệnh chỉ chạy **1 lần** dù có
   nhiều metric cùng dùng chung lệnh đó (ví dụ 2 metric version cùng đọc
   `system diagnostics show version-info`).
6. Trích giá trị bằng regex theo kiểu đã khai (`raw_number`,
   `field_string`, `field_number`, `delta`), cập nhật Gauge.
7. `exit` khỏi Device Console, quay về Main Menu, logout.

## Cấu hình

`config.yml` **chỉ cần thông tin xác thực** cho mỗi thiết bị — luồng đăng
nhập/điều hướng và bộ metric mặc định đã hard-code sẵn trong `app.py`:

```yaml
targets:
  - name: fw1
    host: 192.168.1.1
    port: 22
    username: admin
    password: "CHANGE_ME"
    poll_interval: 30

  - name: fw2
    host: 192.168.2.1
    username: admin
    password: "CHANGE_ME"
```

Muốn tuỳ biến cho 1 thiết bị cụ thể (luồng đăng nhập khác, thêm bước xác
nhận, prompt khác...), ghi đè ngay trong block target đó:

```yaml
targets:
  - name: fw_dac_biet
    host: 192.168.9.1
    username: admin
    password: "CHANGE_ME"
    console_prompt: 'console>\s*'
    menu_navigation:
      - expect: "[Pp]assword:"
        send: "{password}"
      - expect: "Select Menu Number"
        send: "4"
      - expect: "ontinue.*Y/N"      # buoc xac nhan bo sung, neu co
        send: "Y"
        optional: true
```

Có thể ghi đè cả bộ metric (`metrics:` ở cấp global hoặc trong từng
target) nếu không muốn dùng 4 metric mặc định — xem chi tiết 4 kiểu
(`raw_number` / `field_string` / `field_number` / `delta`) trong phần
*Thêm metric mới* bên dưới.

## Cài đặt & chạy thử

Yêu cầu: Python 3.9+, `ssh` (OpenSSH client) có sẵn trên máy chạy exporter.

```bash
git clone <repo-url> sophos-ssh-exporter
cd sophos-ssh-exporter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# sua config.yml: dien host/username/password cho tung thiet bi
python app.py --config config.yml --port 9200
```

Kiểm tra:

```bash
curl http://localhost:9200/metrics
```

Bật log chi tiết khi cần debug:

```bash
python app.py --config config.yml --port 9200 --debug
```

## Triển khai dạng service (systemd)

1. **Copy code vào vị trí cố định** (ví dụ `/opt/sophos-ssh-exporter`):

   ```bash
   sudo mkdir -p /opt/sophos-ssh-exporter
   sudo cp app.py config.yml requirements.txt /opt/sophos-ssh-exporter/
   ```

2. **Tạo virtualenv và cài dependencies**:

   ```bash
   cd /opt/sophos-ssh-exporter
   sudo python3 -m venv venv
   sudo ./venv/bin/pip install -r requirements.txt
   ```

3. **Tạo user hệ thống riêng** để chạy service (không có quyền đăng nhập):

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin sophos-exporter
   ```

4. **Set quyền** — `config.yml` chứa password nên chỉ user chạy service mới
   đọc được:

   ```bash
   sudo chown -R sophos-exporter:sophos-exporter /opt/sophos-ssh-exporter
   sudo chmod 600 /opt/sophos-ssh-exporter/config.yml
   ```

5. **Cài file unit** `sophos-ssh-exporter.service` (đã có sẵn trong repo)
   vào `/etc/systemd/system/`:

   ```ini
   [Unit]
   Description=Sophos Firewall SSH Prometheus Exporter
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=sophos-exporter
   Group=sophos-exporter
   WorkingDirectory=/opt/sophos-ssh-exporter
   ExecStart=/opt/sophos-ssh-exporter/venv/bin/python /opt/sophos-ssh-exporter/app.py --config /opt/sophos-ssh-exporter/config.yml --port 9200
   Restart=on-failure
   RestartSec=5
   StandardOutput=journal
   StandardError=journal

   NoNewPrivileges=yes
   ProtectSystem=full
   ProtectHome=true
   PrivateTmp=true

   [Install]
   WantedBy=multi-user.target
   ```

   ```bash
   sudo cp sophos-ssh-exporter.service /etc/systemd/system/
   ```

6. **Reload systemd và bật service**:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sophos-ssh-exporter
   ```

7. **Kiểm tra**:

   ```bash
   sudo systemctl status sophos-ssh-exporter
   sudo journalctl -u sophos-ssh-exporter -f
   curl http://localhost:9200/metrics
   ```

Quản lý sau khi đã chạy:

```bash
sudo systemctl restart sophos-ssh-exporter   # ap dung sau khi sua config.yml / app.py
sudo systemctl stop sophos-ssh-exporter
sudo systemctl disable sophos-ssh-exporter   # tat tu khoi dong cung he thong
```

## Tích hợp Prometheus

```yaml
scrape_configs:
  - job_name: "sophos_ssh_exporter"
    static_configs:
      - targets: ["sophos-ssh-exporter-host:9200"]
```

Vì dữ liệu đã được các poller thread cache sẵn cho mọi target khai trong
`config.yml`, Prometheus chỉ cần scrape **một** địa chỉ exporter, không
cần pattern `?target=` kiểu blackbox_exporter.

## Thêm metric mới

Bốn kiểu trích xuất đang hỗ trợ:

| Kiểu | Dùng khi | Ví dụ |
|---|---|---|
| `raw_number` | Toàn bộ output chỉ có 1 dòng số | `sophos_sys_ses_count` |
| `field_string` | Lấy chuỗi sau `:` của 1 dòng có nhãn cụ thể | `sophos_sys_version_av` |
| `field_number` | Giống `field_string` nhưng ép về số | *(tuỳ chọn)* |
| `delta` | Hiệu số của 1 metric khác giữa 2 lần poll | `sophos_sys_ses_rate1` |

Có 2 cách thêm:

**Cách 1 — sửa `DEFAULT_METRICS` trong `app.py`** (áp dụng cho mọi thiết
bị, không cần đụng config):

```python
{
    "name": "sophos_sys_cpu_percent",
    "help": "CPU usage percent",
    "type": "field_number",
    "command": "system diagnostics show cpu-usage",
    "label": "CPU usage",
},
```

**Cách 2 — khai trong `config.yml`** (không cần sửa code, có thể áp dụng
riêng cho từng target):

```yaml
metrics:
  - name: sophos_sys_cpu_percent
    help: "CPU usage percent"
    type: field_number
    command: "system diagnostics show cpu-usage"
    label: "CPU usage"
```

Mẹo: SSH tay vào Device Console, chạy đúng lệnh, xem output thật rồi mới
viết `label` — chép chính xác text trước dấu `:` (kể cả hoa/thường) để
tránh khớp nhầm dòng khác.

## Ghi chú kỹ thuật (đã từng gặp và đã fix)

Sau khi chọn `4` để vào Device Console, thiết bị in lại banner (Firmware
Version / Model / Hostname) rồi mới hiện prompt `console>` **trước khi**
lệnh đầu tiên được gửi đi. Nếu không "hứng" hết banner này bằng 1 lần
`expect(console_prompt)` ngay sau khi vào console, output của các lệnh sẽ
bị lệch một nhịp: kết quả của lệnh A lại bị gán nhầm cho lệnh B. Bản hiện
tại đã xử lý đúng bước đồng bộ này (xem `collect_once()` trong `app.py`).

## Bảo mật

- Nên tạo tài khoản SSH riêng trên firewall, quyền thấp nhất đủ chạy lệnh
  chẩn đoán (không cần quyền quản trị đầy đủ).
- Giới hạn IP được phép SSH tới thiết bị chỉ cho máy chạy exporter.
- `config.yml` chứa password dạng plain-text — nên `chmod 600`, giới hạn
  quyền đọc cho user chạy service; có thể sửa `load_config()` để đọc từ
  biến môi trường hoặc secret manager nếu triển khai production.
- Exporter dùng `StrictHostKeyChecking=no` khi SSH (do các thiết bị dùng
  chứng chỉ tự ký) — chấp nhận được trong mạng nội bộ tin cậy, cân nhắc
  pin host key nếu triển khai ở môi trường yêu cầu bảo mật cao hơn.

## Giới hạn hiện tại

- Chỉ lấy được những gì **xem được qua CLI** dưới dạng dòng chữ có cấu
  trúc rõ ràng (`Nhãn: giá trị` hoặc `Nhãn = giá trị`); output dạng bảng
  nhiều cột phức tạp cần viết thêm logic trích xuất riêng.
- `sophos_sys_ses_rate1` là hiệu số đơn giản giữa 2 lần poll (không chia
  cho thời gian), đúng theo yêu cầu ban đầu — không phải "rate/giây" theo
  đúng nghĩa OID SNMP gốc của FortiGate.
- Chưa hỗ trợ SSH key-based auth (hiện chỉ dùng password) — có thể bổ
  sung nếu cần.

## License

Thêm license phù hợp với repo của bạn (MIT, Apache-2.0...).
