# Chạy N91 Portal trên Proxy Linux

Gói này chứa frontend đã build, mã backend Python, cấu hình Nginx và systemd. Mặc định Nginx nghe tại `127.0.0.1:5188` và API tại `127.0.0.1:8188`. Bạn mở Portal qua SSH tunnel từ Windows. Gói P0-10 được build với `--without-seed`. Installer tạo tệp P16H trống cho cài mới. Đặt nguồn audit đã chuẩn hóa trên Proxy theo cấu hình bên dưới.

Máy Proxy cần Linux có systemd, Nginx với `/etc/nginx/conf.d`, Python 3.10 trở lên và mô-đun `venv`. Bước cài dùng pip để lấy phụ thuộc Python từ index đã cấu hình. Kiểm tra hai cổng 5188 và 8188 còn trống trước khi cài.

## Cài lần đầu

Copy gói phát hành và file `.sha256` vào cùng thư mục trên Proxy. Trên Proxy, kiểm mã băm trước khi giải nén. Ví dụ với gói P0-10:

```bash
sha256sum -c n91-portal-p0-10-20261112.tar.gz.sha256
tar -xzf n91-portal-p0-10-20261112.tar.gz
cd n91-portal-p0-10-20261112
sudo bash install.sh
```

Installer kiểm SHA256, đặt code tại `/opt/n91-portal`, config tại `/etc/n91-portal` và dữ liệu Portal tại `/var/lib/n91-portal`. Tạo tài khoản đăng nhập Portal bằng lệnh sau, nhập mật khẩu trực tiếp khi được hỏi:

```bash
cd /opt/n91-portal/backend
sudo -u n91-portal /opt/n91-portal/.venv/bin/python -m app.n91_business.bootstrap \
  --database /var/lib/n91-portal/business.sqlite3 --context PORTAL \
  --username portal-admin --role Analyst --portal-admin
```

Chạy một lượt xuất P17 để kiểm quyền đọc SQLite của service account:

```bash
sudo systemctl start n91-portal-p17.service
sudo systemctl show n91-portal-p17.service -p Result -p ExecMainStatus
```

Khi lượt xuất thành công, bật cập nhật định kỳ và khởi động Portal:

```bash
sudo systemctl enable --now n91-portal-p17.timer n91-portal.service
sudo systemctl start nginx
sudo systemctl reload nginx
curl -fsS http://127.0.0.1:5188/healthz
```

Nếu lượt xuất P17 lỗi, xem `sudo journalctl -u n91-portal-p17.service -n 30 --no-pager`. Kiểm tra đường dẫn DB và quyền đọc của `n91-portal` qua cơ chế cấp quyền hiện có trên Proxy, gồm quyền vào thư mục và đọc sidecar SQLite nếu có. Service chỉ đọc DB nguồn và ghi snapshot ở thư mục Portal riêng. Có thể chạy Portal trước để xem P16H, rồi bật timer P17 khi kiểm tra quyền thành công. Khi timer lỗi, giữ file P17 cuối cùng và dùng journal để kiểm tra. Portal hiển thị P17 dưới dạng snapshot với thời điểm xuất.

## Mở trên Windows

```powershell
ssh.exe -N -J controller@CONTROLLER_HOST -L 5188:127.0.0.1:5188 ubuntu@PROXY_HOST
```

Giữ cửa sổ SSH mở, truy cập `http://127.0.0.1:5188/` và đăng nhập. Mở `/#/events?source=canonical` để xem P16H snapshot. Portal v4 hiển thị P17 sau khi bộ xuất tạo được snapshot. Cấu hình session của bản này khóa đường dẫn console, kể cả WebSocket.

## Nguồn bổ sung

- **OpenStack:** điền `OPENSTACK_*` trong `/etc/n91-portal/portal.env` rồi restart `n91-portal.service`. Credential reader đặt riêng tại Proxy và giới hạn quyền đọc cho `n91-portal`. Kiểm tra kết nối Keystone, Nova, Neutron từ Proxy trước khi bật `OPENSTACK_INVENTORY_ENABLED=true`.
- **P16H:** đặt JSONL chuẩn hóa tại đường dẫn `AUDIT_PATH` và cấp quyền đọc cho `n91-portal`. Cấu hình mặc định là snapshot lịch sử. Reader `RECENT/HEALTH` cần được cấu hình và nghiệm thu riêng.
- **RC5 và Controller:** cấu hình artifact đã kiểm với `PORTAL_INVESTIGATION_POLICY`, `PORTAL_INVESTIGATION_POLICY_SHA256`, `PORTAL_INVESTIGATION_POLICY_VERSION`, `PORTAL_INVESTIGATION_CONTROLLER` và `PORTAL_INVESTIGATION_CONTROLLER_SHA256` khi có dữ liệu.
- **Kiểm chứng chức năng:** đặt `PORTAL_DEFENSE_SOURCE_REGISTRY` và `PORTAL_DEFENSE_ARCHIVE_DIR` tới registry và thư mục bundle 07D trên Proxy. Health dùng `PROXY_SERVICES_PATH` và `GALERA_SNAPSHOT_DIR` khi có bản chụp. Ví dụ đường dẫn nằm trong `portal.env.example`.

Khi cần cung cấp Portal qua một địa chỉ mạng chung, cấu hình HTTPS trên reverse proxy, đặt `CORS_ORIGINS` đúng origin công bố và `PORTAL_SESSION_LOCAL_HTTP=false`. Uvicorn cần nhận `X-Forwarded-Proto` chỉ từ reverse proxy tin cậy để nhận diện HTTPS. Bản mặc định phục vụ kiểm tra qua SSH tunnel.

## Thu thập bản chụp Galera

Lấy `backend/collect_galera_snapshot.py` từ checkout Git và chép vào từng node `galera-1`, `galera-2`, `galera-3`. Chạy trên mỗi node bằng tài khoản có quyền đọc MariaDB qua socket cục bộ:

```bash
sudo -v
python3 collect_galera_snapshot.py > "$(hostname).json"
```

Bộ thu thập ghi thời điểm đo và tám trường wsrep theo schema `portal-galera-node-1`. Kiểm tra cả ba file có `read_ok: true`, rồi chuyển `galera-1.json`, `galera-2.json`, `galera-3.json` vào thư mục riêng trên Proxy mà tiến trình Portal đọc được. Nếu Proxy không truy cập được SSH của các node, lấy các file qua Controller rồi chuyển về Proxy.

Đặt `GALERA_SNAPSHOT_DIR` thành đường dẫn tuyệt đối của thư mục trong file môi trường mà tiến trình Portal đang sử dụng. Khởi động lại Portal sau khi thêm hoặc đổi đường dẫn. Mở `/#/system/galera` và kiểm tra đủ ba node, đủ tám trường và thời điểm đo khớp với các file. Portal hiển thị kết quả theo thời điểm đo với nhãn `SNAPSHOT` / `HISTORICAL`.

Controller đọc ba node song song. Timer đợi 15 giây sau khi lượt đo kết thúc rồi chạy lượt tiếp theo. Trên Controller, đặt `backend/galera_periodic.py` tại `/opt/portal-galera/galera_periodic.py` và tạo `/etc/portal-galera/collector.env` với `GALERA_SSH_KEY` là đường dẫn tuyệt đối, `GALERA_1`, `GALERA_2`, `GALERA_3`, `GALERA_PROXY` là các đích `user@host`. Cài `portal-galera.service` và `portal-galera.timer` trong gói trên Controller, rồi chạy `sudo systemctl daemon-reload` và `sudo systemctl enable --now portal-galera.timer`. Nếu đã có timer đang hoạt động, kiểm tra bằng `systemctl cat portal-galera.service portal-galera.timer` và cập nhật script ở đường dẫn hiện tại.

Dùng khóa SSH riêng với `restrict,command="..."` trong `authorized_keys`. Mỗi node chỉ chạy bộ đọc wsrep qua socket; Proxy chỉ chạy `backend/galera_periodic.py receive <GALERA_SNAPSHOT_DIR>` với Python và `PYTHONPATH` của Portal. Kiểm tra và lưu host key trước khi bật timer. Proxy giữ ba file JSON, từ chối batch cũ hoặc phát lại, và khóa thư mục khi ghi. Kiểm tra `journalctl -u portal-galera.service -n 30` và xác nhận Portal nhận hai batch mới liên tiếp. Quá 45 giây, trạng thái cụm trở về chưa xác minh. Hai node cùng báo Primary với kích thước 2 có thể xác nhận cụm suy giảm; lỗi SSH của node thứ ba vẫn hiển thị riêng.

## Proxy chạy `portal-local`

Lab từng dùng Uvicorn `local_app:app` ở `/home/ubuntu/portal-local`, với Python `.venv313/bin/python` và gói `n91-portal-proxy-linux/{backend,web}`. Checkout `~/portal` là nơi lấy mã. Xác nhận lại listener và module trước khi nâng cấp:

```bash
ss -ltnp 'sport = :5188'
# Thay PID bằng PID listener đã xác nhận.
readlink -f /proc/PID/cwd
tr '\0' '\n' </proc/PID/cmdline
rg -n '^(from|import) (app|fastapi)|create_app|StaticFiles' ~/portal-local/local_app.py
```

Nếu launcher nhập `app.main`, giữ nguyên launcher và kiểm tra đường dẫn import trong đúng venv trước khi đổi bản. Xác nhận bằng `/healthz`, `/api/v1/system/build`, `/api/v1/system/galera` và trang **Hệ thống → Nguồn dữ liệu** qua tunnel. Nếu launcher tự khai báo route, đối chiếu route và source của launcher trước khi thay gói. Installer systemd bên dưới dành cho layout riêng.

Kiểm tra checksum gói trong thư mục staging. Khi đóng gói từ commit sạch, manifest ghi SHA commit nguồn và hash thực tế của backend/frontend. Với `portal-local`, trỏ `PORTAL_BUILD_MANIFEST` vào `backend/portal-build.json` trong gói đang chạy. SHA của collector để trống đến khi đối chiếu được bản đang chạy trên Controller. Giữ bản gói trước và sao lưu DB/config theo chính sách của lab; đặt bản đã kiểm checksum vào đúng đường dẫn đang phục vụ rồi khởi động lại bằng lệnh đã xác minh. Nếu receiver tham chiếu `~/portal/backend/galera_periodic.py`, cập nhật API backend có `batch_lock` trước khi chuyển receiver sang mã mới, hoặc chuyển forced command sang bản receiver cùng gói. Khi quay lại, khôi phục backend, web và receiver tương thích với nhau, sau đó kiểm lại build và DB.

Nút **Cô lập** và **Khôi phục** dùng session có vai trò `Executor` và CSRF. Tài khoản `Viewer` xem trạng thái và lịch sử. Trên demo, allowlist chỉ chứa UUID của `p17-lab-clone` và mặc định để trống ở môi trường khác. Dùng application credential riêng có role `member` trong đúng project, lưu JSON với các trường `id`, `secret`, `project_id` và quyền `0600`. Security Group cô lập phải thuộc project và không có rule. Neutron cần extension `revision-if-match`.

Trên `portal-local`, tạo Business DB riêng và tài khoản quản trị đầu tiên nếu DB chưa tồn tại:

```bash
cd /home/ubuntu/portal-local/n91-portal-proxy-linux/backend
/home/ubuntu/portal-local/.venv313/bin/python -m app.n91_business.bootstrap \
  --database /home/ubuntu/portal-local/business.sqlite3 --context PORTAL \
  --username portal-admin --role Analyst --portal-admin
```

Tạo tài khoản `Executor` và `Viewer` trong **Quản trị Portal** bằng phiên quản trị. Giữ các biến đọc hiện có và bổ sung vào `openstack.env`:

```dotenv
PORTAL_SESSION_AUTH=true
PORTAL_SESSION_LOCAL_HTTP=true
PORTAL_BUSINESS_DATABASE=/home/ubuntu/portal-local/business.sqlite3
CORS_ORIGINS=http://127.0.0.1:5188
OPENSTACK_QUARANTINE_CREDENTIAL_PATH=/home/ubuntu/portal-local/openstack-quarantine-member.json
OPENSTACK_QUARANTINE_SG_ID=6e72bfd2-0b73-47e8-9fe9-7f3b83337892
PORTAL_QUARANTINE_ALLOWED_SERVER_IDS=fa34f3e8-50ff-467e-a7db-a5cd92613682
PORTAL_QUARANTINE_TTL_SECONDS=90
```

Sao lưu release và file môi trường, đồng thời dùng SQLite backup API để sao lưu DB audit và Business DB trước khi thay bản. Kiểm checksum gói CI, restart đúng launcher đang dùng với lifespan Uvicorn bật, rồi xác minh `SESSION`, `workload_quarantine_available=true` và SHA qua `/api/v1/system/build` sau đăng nhập. Chạy lại Events, Incidents, Galera và Workloads với phiên đăng nhập.

Portal lưu SG gốc theo từng port trước khi ghi Neutron. Tác vụ nền đọc các lượt quá hạn mỗi 2 giây và tiếp tục từ Business DB sau restart. Khi Portal dừng quá TTL, tác vụ chạy lại khi Portal lên. Kiểm tra cả khôi phục thủ công và một lượt khôi phục theo TTL sau khi restart, kèm đối chiếu SG trực tiếp trong Neutron, lịch sử `NORMAL → QUARANTINED → NORMAL` và audit `WORKLOAD_QUARANTINE` / `WORKLOAD_RESTORE`. Nếu port hoặc revision thay đổi ngoài lượt thử, Portal giữ trạng thái lỗi và thông tin SG gốc để người vận hành đối chiếu.

Trước khi rollback, khôi phục và xác minh hết các lượt còn mở. Nếu Portal không hoạt động, dùng bản ghi SG gốc trong Business DB hoặc audit để gắn lại bằng Neutron CLI với phiên vận hành đã được cấp quyền. Đối chiếu port, project, SG và revision hiện tại trước khi ghi. Sau đó mới quay lại bundle và cấu hình trước đó. Giữ Business DB và audit của lượt mới để đối chiếu.

Khi bật inventory và cấu hình UUID SG cô lập, API lấy mẫu nền khoảng 3 giây một lần và lưu tối đa 50 mục lịch sử cho mỗi VM trong SQLite của Portal. Giao diện hiển thị 10 mục gần nhất. Nút Cô lập ghi riêng lần Neutron xác nhận, nên lần đó vẫn có trong lịch sử sau khi Watchdog khôi phục. Với thao tác từ Controller hoặc Watchdog, Portal chỉ ghi những trạng thái bộ thu quan sát được. Một lần cô lập xảy ra hoàn toàn giữa hai mẫu có thể bị bỏ lỡ. Thời điểm trong lịch sử là lúc quan sát, không phải thời điểm Neutron bắt đầu áp dụng luật.

Với P16H, đối chiếu `AUDIT_MODE`, nguồn ghi `AUDIT_PATH` và thời gian sự kiện/nhập trong API. Dùng bộ lọc thời gian, IP và tài khoản trên `/#/events?source=canonical` để đối chiếu từng lệnh SQL mới. Ghi mã yêu cầu nếu nguồn có cấp. P17 projection là nguồn bổ sung khi thiếu bản ghi canonical.

## Nâng cấp

Installer dành cho cài mới. Các bước dưới đây áp dụng cho bản chạy từ
`/opt/n91-portal` với unit `n91-portal.service`.

1. Kiểm checksum gói, giải nén vào thư mục riêng và chạy `sha256sum -c SHA256SUMS`
   trong thư mục đó. Ghi lại unit, đường dẫn venv, config và trạng thái timer
   đang sử dụng. Dàn sẵn `backend`, `web` và môi trường Python cho bản mới.
2. Dừng API và timer xuất snapshot của Portal, chờ lượt xuất đang chạy kết thúc.
   Sao lưu code, venv, config và dữ liệu Portal gồm `business.sqlite3`. Sao lưu
   khi service đã dừng để giữ nhất quán giữa DB và các sidecar SQLite.
3. Đặt `backend` và `web` mới vào đường dẫn unit và Nginx đang dùng. Giữ bản cũ
   ở đường dẫn riêng để quay lại. Cài phụ thuộc trong venv Linux và bổ sung các
   đường dẫn nguồn cần thiết vào file cấu hình đang dùng.
4. Nếu có Business DB schema 1, chạy migration với interpreter và tài khoản
   của service. Dùng đúng đường dẫn `PORTAL_BUSINESS_DATABASE` nếu cấu hình đã đổi.

   ```bash
   cd /opt/n91-portal/backend
   sudo -u n91-portal /opt/n91-portal/.venv/bin/python -m app.n91_business.bootstrap \
     --database /var/lib/n91-portal/business.sqlite3 --context PORTAL --migrate-only
   ```

5. Chạy `sudo nginx -t`, khởi động lại API và khôi phục trạng thái timer trước
   nâng cấp. Kiểm `curl -fsS http://127.0.0.1:5188/healthz` và kiểm qua SSH
   tunnel. Đăng nhập, mở hồ sơ sự cố, kiểm ghi chú/phân công/trạng thái đọc,
   tải bằng chứng JSON/CSV và mở **Hệ thống → Kiểm chứng chức năng**. Xác nhận
   các nguồn đúng phạm vi và các nguồn thiếu được báo rõ. `/healthz` kiểm tiến
   trình API. Health chức năng của SQL/TLS được kiểm riêng.

Khi cần quay lại, dừng API/timer và lưu bản sao DB vừa nâng cấp. Khôi phục code,
web, venv, config và bản Business DB trước migration cùng nhau. Bản cũ chỉ nhận
schema 1. Khởi động lại và kiểm đăng nhập cùng `/healthz`. Các thay đổi hồ sơ
sau migration nằm trong bản sao DB schema 2 đã lưu.

## Build khác run dev

`npm run dev` chạy Vite, cập nhật ngay khi bạn sửa code và chuyển tiếp `/api` trong lúc phát triển. `npm run build` biên dịch React thành HTML, JavaScript và CSS trong `dist`. Bản gói dùng các file đã build để Nginx phục vụ, vì vậy trên Proxy chỉ cần web server và Python backend. Các API, DB và dữ liệu nguồn được cấu hình lúc chạy.
