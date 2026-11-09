# Chạy N91 Portal trên Proxy Linux

Gói này chứa frontend đã build, mã backend Python, cấu hình Nginx và systemd. Mặc định Nginx nghe tại `127.0.0.1:5188` và API tại `127.0.0.1:8188`. Bạn mở Portal qua SSH tunnel từ Windows. Cài đặt tạo một file P16H rỗng. Sau khi cài, cung cấp snapshot đã kiểm tra từ hệ thống của bạn để hiển thị dữ liệu.

Máy Proxy cần Linux có systemd, Nginx với `/etc/nginx/conf.d`, Python 3.10 trở lên và mô-đun `venv`. Bước cài dùng pip để lấy phụ thuộc Python từ index đã cấu hình. Kiểm tra hai cổng 5188 và 8188 còn trống trước khi cài.

## Cài lần đầu

Copy file `n91-portal-proxy-linux.tar.gz` đến thư mục home trên Proxy. Thay JUMP_HOST và PROXY_HOST bằng địa chỉ của bạn, rồi chạy trong PowerShell từ thư mục repo:

```powershell
scp.exe -J controller@JUMP_HOST ./deploy/n91-portal-proxy-linux.tar.gz ubuntu@PROXY_HOST:~/
```

Trên Proxy:

```bash
tar -xzf n91-portal-proxy-linux.tar.gz
cd n91-portal-proxy-linux
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
ssh.exe -N -J controller@JUMP_HOST -L 5188:127.0.0.1:5188 ubuntu@PROXY_HOST
```

Giữ cửa sổ SSH mở, truy cập `http://127.0.0.1:5188/` và đăng nhập. Mở `/#/events?source=canonical` để xem P16H snapshot. Portal v4 hiển thị P17 sau khi bộ xuất tạo được snapshot. Cấu hình session của bản này khóa đường dẫn console, kể cả WebSocket.

## Nguồn bổ sung

- **OpenStack:** điền `OPENSTACK_*` trong `/etc/n91-portal/portal.env` rồi restart `n91-portal.service`. Credential reader đặt riêng tại Proxy và giới hạn quyền đọc cho `n91-portal`. Kiểm tra kết nối Keystone, Nova, Neutron từ Proxy trước khi bật `OPENSTACK_INVENTORY_ENABLED=true`.
- **P16H tự cập nhật:** cần tích hợp reader `RECENT/HEALTH` và xác nhận đường đọc live. Để dùng snapshot đã kiểm tra, đặt JSONL chuẩn hóa tại /var/lib/n91-portal/p16h-import.jsonl với quyền đọc cho n91-portal, rồi khởi động lại API.
- **RC5 và Controller:** cấu hình artifact đã kiểm với `PORTAL_INVESTIGATION_POLICY`, `PORTAL_INVESTIGATION_POLICY_SHA256`, `PORTAL_INVESTIGATION_POLICY_VERSION`, `PORTAL_INVESTIGATION_CONTROLLER` và `PORTAL_INVESTIGATION_CONTROLLER_SHA256` khi có dữ liệu.

Khi cần cung cấp Portal qua một địa chỉ mạng chung, cấu hình HTTPS trên reverse proxy, đặt `CORS_ORIGINS` đúng origin công bố và `PORTAL_SESSION_LOCAL_HTTP=false`. Uvicorn cần nhận `X-Forwarded-Proto` chỉ từ reverse proxy tin cậy để nhận diện HTTPS. Bản mặc định phục vụ kiểm tra qua SSH tunnel.

## Nâng cấp

Installer dành cho cài mới. Để nâng cấp bản đã cài, sao lưu `/etc/n91-portal/portal.env`, dữ liệu `/var/lib/n91-portal` và code đang chạy. Dừng các service Portal, triển khai `web` và `backend` của bản mới, cài phụ thuộc vào venv và xác minh `nginx -t` trước khi chạy lại. Giữ DB tài khoản và các đường dẫn nguồn đã cấu hình.

## Build khác run dev

`npm run dev` chạy Vite, cập nhật ngay khi bạn sửa code và chuyển tiếp `/api` trong lúc phát triển. `npm run build` biên dịch React thành HTML, JavaScript và CSS trong `dist`. Bản gói dùng các file đã build để Nginx phục vụ, vì vậy trên Proxy chỉ cần web server và Python backend. Các API, DB và dữ liệu nguồn được cấu hình lúc chạy.
