# sophos_ssh_exporter

Prometheus exporter viết bằng Python, lấy metric từ **Sophos Firewall**
bằng cách SSH thẳng vào CLI thiết bị (không dùng SNMP) - dựa theo mô hình
["multi-target exporter"](https://prometheus.io/docs/guides/multi-target-exporter/)
giống Blackbox Exporter: một tiến trình exporter duy nhất, phục vụ nhiều
thiết bị thông qua endpoint `/scrape?target=<ip>&module=<module>`.

## Metric lấy được

| Metric | Loại | Nguồn |
|---|---|---|
| `sophos_sys_ses_count` | Gauge | `system diagnostics utilities connections count` |
| `sophos_sys_ses_rate1` | Gauge (delta) | chênh lệch `sophos_sys_ses_count` so với lần scrape trước |
| `sophos_sys_version_av{version=...}` | Info-style Gauge | `system diagnostics show version-info`, dòng `Sophos AV` |
| `sophos_sys_version_ips{version=...}` | Info-style Gauge | cùng lệnh trên, dòng `IPS and Application signatures` |
| `entPhysicalMfgName{entPhysicalMfgName=...}` | Info-style Gauge | `ethtool -m <port>` (Advanced Shell), dòng `Vendor name` |
| `entPhysicalModelName{entPhysicalModelName=...}` | Info-style Gauge | cùng lệnh, dòng `Vendor PN` |
| `entPhysicalName{entPhysicalName=...}` | Info-style Gauge | tên port quang tương ứng |
| `sophos_ssh_scrape_success` | Gauge | 1 nếu lần scrape thành công, 0 nếu lỗi SSH |
| `sophos_ssh_scrape_duration_seconds` | Gauge | thời gian scrape mất bao lâu |

Ba metric `entPhysical*` được thiết kế để **join lại với nhau bằng PromQL**
(giống cách `snmp_exporter` phơi bày entity MIB của FortiGate), ví dụ:

```promql
(
  entPhysicalMfgName{device_type="firewall", entPhysicalMfgName!=""}
  * on(entPhysicalIndex, instance, job, device_name) group_left(entPhysicalModelName)
  entPhysicalModelName{device_type="firewall", entPhysicalModelName!=""}
)
* on(entPhysicalIndex, instance, job, device_name) group_left(entPhysicalName)
entPhysicalName{device_type="firewall", entPhysicalName!=""}
```

## Cách hoạt động

Với mỗi request `/scrape`, exporter:

1. Mở phiên SSH tới `target`, đăng nhập bằng `username`/`password` khai
   trong `module`.
2. Vào **Main Menu → 4 (Device Console)**, chạy các lệnh CLI chẩn đoán để
   lấy `sophos_sys_*`.
3. Thoát về Main Menu, vào **5 (Device Management) → 3 (Advanced Shell)**,
   chạy `ethtool -m <port>` lần lượt cho danh sách port quang cố định sẵn
   trong code: `PortA1..PortA8`, `PortF1..PortF4`, `PortB1..PortB4`.
4. Thoát phiên, trả toàn bộ metric về dạng Prometheus text format.

Mỗi request dùng một `CollectorRegistry` riêng (tránh lỗi đăng ký trùng
metric giữa các lần scrape đồng thời). Giá trị "lần trước" dùng để tính
`sophos_sys_ses_rate1` được lưu trong bộ nhớ tiến trình (`_target_state`),
theo từng `target`.

## Yêu cầu

- Python 3.9+
- Gói pip: `flask`, `pexpect`, `pyyaml`, `prometheus_client`
- Máy chạy exporter cần có sẵn lệnh `ssh` (dùng `pexpect.spawn` gọi ra
  binary `ssh` hệ thống, không dùng thư viện SSH thuần Python).

```bash
pip install flask pexpect pyyaml prometheus_client
```

## Cài đặt & chạy thử

```bash
git clone <repo-nay>
cd <repo-nay>
cp config.example.yml config.yml    # sua username/password that
python app.py --config config.yml --port 9200
```

Kiểm tra thử một thiết bị:

```bash
curl "http://127.0.0.1:9200/scrape?target=10.121.1.250&module=default"
```

## Cấu hình `config.yml`

File này **chỉ khai "modules"** (bộ thông tin đăng nhập dùng chung), KHÔNG
khai danh sách thiết bị - danh sách IP nằm bên phía `prometheus.yml` (xem
mục dưới). Mỗi module có thể dùng cho nhiều thiết bị nếu chúng cùng
username/password.

```yaml
modules:
  default:
    username: admin
    password: "YourPasswordHere"
    port: 22
    connect_timeout: 15
    command_timeout: 15
```

Nếu có nhóm thiết bị dùng thông tin đăng nhập khác, thêm module khác:

```yaml
modules:
  default:
    username: admin
    password: "PasswordChoNhomA"
  branch_office:
    username: admin
    password: "PasswordChoNhomB"
```

rồi trong `prometheus.yml`, tách thành 2 `scrape_configs` khác nhau, mỗi
cái dùng `module` tương ứng và `static_configs` liệt kê đúng nhóm IP của
module đó.

## Cấu hình Prometheus

```yaml
scrape_configs:
  - job_name: 'sophos_ssh_exporter'
    scrape_interval: 60s
    scrape_timeout: 45s       # QUAN TRỌNG: phải đủ lớn vì SSH + duyệt menu CLI tốn thời gian
    metrics_path: /scrape
    params:
      module: [default]       # tên module khai trong config.yml
    static_configs:
      - targets:
          - 10.121.1.250      # IP thiết bị Sophos thật
          - 10.121.1.251
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9200   # dia chi:port noi sophos_ssh_exporter dang chay
```

Bốn bước `relabel_configs` này là mẫu chuẩn của mọi multi-target exporter:
Prometheus tưởng như đang scrape thẳng `10.121.1.250:9200/scrape`
(`__address__` ban đầu), nhưng relabel sẽ:

1. Chuyển `__address__` (chính là IP thiết bị) thành tham số
   `?target=10.121.1.250`.
2. Gán IP đó vào label `instance` để phân biệt series trên Grafana.
3. Đổi `__address__` thật thành nơi exporter đang chạy
   (`127.0.0.1:9200`), để Prometheus gọi đúng tiến trình exporter chứ
   không cố kết nối SSH trực tiếp vào chính thiết bị.

## Giới hạn hiện tại (cần biết trước khi dùng)

- **Danh sách port quang cố định trong code** (`PortA1-8`, `PortF1-4`,
  `PortB1-4`), sửa trực tiếp trong hàm `collect_from_target()` nếu thiết
  bị khác có dải port khác.
- **`entPhysicalIndex` là số thứ tự 1..16** theo vị trí trong danh sách
  port cố định đó, KHÔNG phải tên port thật - tên port thật nằm ở
  `entPhysicalName`.
- **`device_type="firewall"`, `job="firewall"`, `vendor="sophos"` bị
  hardcode** trong code, chưa đọc từ `config.yml` - nếu có nhiều loại
  thiết bị khác nhau (switch, firewall khác hãng...) cần sửa code để
  nhận nhãn từ cấu hình thay vì cố định.
- **`password` lưu dạng plaintext trong `config.yml`** - nên giới hạn
  quyền đọc file (`chmod 600 config.yml`) và không commit file thật (chỉ
  commit `config.example.yml`).
- Nếu một thiết bị timeout/lỗi SSH giữa chừng khi Prometheus đang scrape
  nhiều target cùng lúc, request đó sẽ chờ tới hết `command_timeout`/
  `connect_timeout` - đặt `scrape_timeout` trong `prometheus.yml` đủ lớn
  hơn tổng các timeout này.

## Khắc phục sự cố

- **Không thấy `sophos_sys_version_av`/`ips`**: kiểm tra nhãn dòng thật
  trên thiết bị bằng lệnh `system diagnostics show version-info`, đối
  chiếu đúng chữ hoa/thường với `label` khai trong `BUILTIN_METRICS`.
- **Không đọc được SFP (`entPhysicalMfgName` trống)**: chạy tay
  `ethtool -m <ten_port>` trên Advanced Shell (`5` → `3`) để xác nhận
  port đó có thật sự có module quang không, và tên port có đúng định
  dạng `PortA<n>`/`PortF<n>`/`PortB<n>` như code đang gọi không.
- **Scrape luôn timeout**: tăng `connect_timeout`/`command_timeout` trong
  `config.yml` và `scrape_timeout` trong `prometheus.yml`; kiểm tra máy
  chạy exporter SSH thủ công vào thiết bị được không (`ssh admin@<ip>`).
- Bật log chi tiết bằng cách chạy exporter với biến môi trường debug hoặc
  thêm `log.setLevel(logging.DEBUG)` tạm thời để xem toàn bộ output CLI
  thô khi cần chẩn đoán sâu hơn.

## License

Nội bộ - chưa xác định giấy phép công khai.