# Ứng phó tự động và khôi phục máy ảo thử nghiệm

## Trạng thái đã nghiệm thu ngày 21/11/2026

Luồng thật đã hoàn tất: truy vấn từ App thành công, một sự kiện bị chặn chưa
cách ly, chuỗi vi phạm ngữ cảnh bị từ chối phản ứng tự động, chuỗi ba yêu cầu
SQL injection được cấp phép cách ly, App tiếp tục truy vấn thành công, người
quản trị bấm **Khôi phục** trên Portal local và Neutron xác nhận đúng nhóm bảo mật gốc.

- Lần chạy: `N91_AUTO_DEMO_20261121T155136Z`.
- Sự cố được cấp phép: `INC-16fb7a0ba005e944bbcf`.
- Lượt xử lý: `de498685-8940-4fbd-bf2e-eee41d10d991`.
- Cô lập: `2026-11-21T15:52:05.756556Z`.
- Khôi phục thủ công: `2026-11-21T15:56:22.146682Z`.
- Revision cổng mạng: **81 → 82 → 83**, nhóm gốc khôi phục chính xác.
- App trả **4 sản phẩm** trước và trong thời gian clone bị cách ly.
- Phép đo ICMP: 20/20 phản hồi trước xử lý; 0/125 phản hồi trong khoảng
  cách ly ổn định; 22/24 phản hồi sau khôi phục. Các mẫu chuyển tiếp được giữ nguyên.
  Đây là bằng chứng ICMP; không gọi là phép đo TCP hoặc phiên SQL của clone.
- Chỉ một lượt tự động được ghi trong kho Controller; chỉ đúng VM thử nghiệm.

Các JSON và ảnh chứng minh nằm trong thư mục `outputs` của workspace tích hợp.
Hai lần chạy thất bại trước đó được giữ riêng. Lần đầu phát hiện lỗi đối chiếu
mốc thời gian/capture; lần hai gặp cache chặn host MariaDB do phép đo TCP tiền
xác thực lặp lại. Đã sửa đối chiếu theo đúng mốc worker dùng, thay phép đo bằng
ICMP và người vận hành xóa cache lỗi kết nối trên ba node. Không hạ ngưỡng chính sách.

## Phạm vi và luồng thực thi

Proxy chỉ xuất bằng chứng đã lưu và nhật ký kiểm toán chuẩn hóa qua SSH với
lệnh cố định `N91_AUTO_FEED_V1`. Bộ xuất không ACK, không đổi cờ quyền trên
sự cố, không gửi SQL gốc và không thao tác OpenStack. Lệnh đọc cũ vẫn hoạt động.

Controller chạy độc lập `n91-auto-worker.service`. Chính sách
`n91-clone-auto-corr002-v2` chỉ áp dụng VM
`fa34f3e8-50ff-467e-a7db-a5cd92613682`, cổng
`31465b2c-d248-4665-ab0c-f704976c8405`, IP `10.0.0.204`, đúng project và network.
App, Proxy, các node Galera và Controller đều ngoài phạm vi tự động.

Điều kiện cấp phép gồm CORR-002, ít nhất ba yêu cầu/sự kiện/thứ tự độc lập,
cửa sổ nhỏ hơn 60 giây và điểm đỉnh ít nhất 60, đúng phiên bản detector/chính sách,
liên kết bằng chứng được lưu trực tiếp, SHA-256 khớp bản ghi Canonical,
nguồn mới sau mốc kích hoạt và không quá hạn. Mốc kích hoạt hiện tại:
`2026-11-21T15:22:51.982378+00:00`, bỏ qua thứ tự đến **1004**.

Mốc tương quan là `metadata.request_received_at`, đúng mốc detector sử dụng.
Mốc `record.timestamp` là thời gian bản ghi kiểm toán riêng và được lưu riêng.
Bộ xác minh nguồn lấy mẫu Neutron trước và sau cửa sổ yêu cầu, buộc định danh,
revision và Security Group ổn định. Thiếu mẫu hoặc có thay đổi thì chưa cấp phép.

Kho SQLite riêng lưu quyết định, mọi lần đánh giá, ảnh ánh xạ nguồn và nhóm
bảo mật gốc trước khi gọi Neutron. Actor tự động là `SYSTEM_AUTO_P17` trong
nhật ký máy; không giả phiên đăng nhập của người dùng. Cùng một sự cố không
được thực thi lại. Khóa chung bảo vệ worker, giám sát phục hồi và khôi phục từ Portal.

Một phản ứng thành công **không có TTL tự khôi phục**. Chỉ người quản trị bấm
Khôi phục mới trả nhóm gốc. `n91-auto-watchdog.timer` chạy riêng mỗi ba giây
để phục hồi thao tác dang dở/lỗi, kiểm tra revision trước khi ghi và xác minh
lại kết quả. Nó không tháo cách ly thành công theo thời gian.

## Các thành phần source và cấu hình

- `backend/integrations/p17/auto_feed.py`: bản xuất chỉ đọc trên Proxy.
- `backend/app/auto_response.py`: chính sách, xác minh, nhật ký, worker, giám sát phục hồi và RPC.
- `backend/app/auto_remote.py`: Portal đọc trạng thái, nhật ký và khôi phục đúng lượt trên Controller.
- `backend/integrations/openstack_ssh_relay.py`: chỉ nhận ba RPC cố định của luồng này.
- `backend/integrations/p17/n91-auto-*.service` và `.timer`: systemd.
- Bộ chạy nghiệm thu dùng nguồn và phiên thử nghiệm riêng của người vận hành.

Gói mã nguồn GitHub chứa mã vận hành và kiểm thử tự động. Nhật ký nghiệm thu,
cấu hình triển khai và bộ phát lưu lượng thử nghiệm của môi trường thật được lưu riêng.

Trên Proxy, đặt `auto_feed.py` cạnh `p17_feed.py`. Trong đầu hàm `main()`
của file feed hiện hữu, trước lệnh đọc cũ, thêm:

```python
import os, runpy
if os.environ.get('SSH_ORIGINAL_COMMAND') == 'N91_AUTO_FEED_V1':
    runpy.run_path('/home/ubuntu/p17-5-controller-lab-v0.1.0/auto_feed.py', run_name='__main__')
    return
```

Giữ bản sao nguồn trước sửa, chuẩn hóa LF và kiểm tra cú pháp. Không thay
forced command hay mở quyền SSH mới cho collector. Kiểm tra cả lệnh đọc cũ
và lệnh mới sau khi triển khai.

Runtime Controller hiện tại là `/home/controller/.n91-auto-runtime`.
`runtime.env` chỉ định `PYTHONPATH` tới release đã kiểm tra; mã nguồn gồm
package `backend/app` đầy đủ, cài `backend/requirements.txt`. `config.json`
tham chiếu các khóa sau; giá trị credential là **đường dẫn tệp hiện có**, không
phải credential nhúng trong source:

```json
{
  "database_path": "/home/controller/.n91-auto-runtime/state/auto.sqlite3",
  "reader_credential_path": "<reader credential file on Controller>",
  "quarantine_credential_path": "<Member credential file on Controller>",
  "auth_url": "<Keystone v3 URL>",
  "compute_url": "<Nova v2.1 URL>",
  "network_url": "<Neutron URL>",
  "feed_ssh_key": "<existing restricted feed identity>"
}
```

`read_feed()` giới hạn đích Proxy cố định trong mã; đường dẫn khóa lấy từ cấu hình.
Thư mục runtime 0700, file cấu hình/credential 0600. Giữ SQLite ở volume bền vững.
Không tạo người dùng Portal trong kho này. Không dùng OpenStack admin credential.

Relay Controller thêm mục `automatic_response` với `python`, `source`, `config`
trỏ đúng Python/release/config đã triển khai. Local thêm
`PORTAL_AUTOMATIC_RESPONSE_REMOTE=true` vào cấu hình SESSION hiện có.
API `/api/v1/system/automatic-response` yêu cầu phiên đăng nhập. Khôi phục vẫn
qua API workload hiện hữu, kiểm tra quyền, CSRF, Origin và operation ID.

Cài các unit vào `/etc/systemd/system`, chạy `systemctl daemon-reload`, bật timer,
kiểm tra heartbeat, đối chiếu mục tiêu và chạy chế độ `arm` **một lần** trước khi
bật worker. Mọi lần `rearm` phải là quyết định vận hành có chủ đích vì sẽ đổi mốc
bỏ qua. Không chạy lại script triển khai ban đầu trên kho đã có phản ứng.

## Kiểm thử và giới hạn dữ liệu

Backend: **113 passed, 1 skipped**; skip thuộc luồng tích hợp tùy chọn của bộ
kiểm thử hiện hữu. Frontend logic, điều tra, nghiệp vụ, render VM và Vite build
được chạy riêng. Các kiểm thử bảo vệ phạm vi, trùng yêu cầu, cờ quyền, mốc
kích hoạt, hash, ánh xạ/revision, nguồn quá hạn và khôi phục đều giữ cơ chế đóng
khi thiếu bằng chứng. Giám sát phục hồi dang dở được kiểm thử tự động; không
chủ động gây hỏng thao tác OpenStack đang chạy để chứng minh nhánh này trên LAB.

Giao diện dùng tên chức năng tiếng Việt thay mã giai đoạn nội bộ. Source/API,
UUID, hash và các bản xuất gốc giữ nguyên để có thể đối chiếu. Tên hiển thị
“Máy ảo thử nghiệm cách ly” tương ứng VM có UUID nêu trên.

Sự cố cũ thiếu liên kết gốc không được dựng lại thành bằng chứng trực tiếp.
Retention nhật ký, số đo TLS chỉ bắt tay, bản backup chưa thử restore và RPO/RTO
toàn hệ thống chưa đo vẫn phải được trình bày đúng phạm vi trong báo cáo.
