# N91 Portal

Giao diện điều tra và theo dõi nguồn dữ liệu P16H, P17, OpenStack. Backend FastAPI chạy cùng frontend React.

## Cài trên Proxy Linux

Bản P0-10 đã build ở [deploy/n91-portal-proxy-linux.tar.gz](deploy/n91-portal-proxy-linux.tar.gz),
kèm [checksum SHA-256](deploy/n91-portal-proxy-linux.tar.gz.sha256).
Kiểm checksum trong thư mục `deploy` bằng
`sha256sum -c n91-portal-proxy-linux.tar.gz.sha256`. Gói giải nén thành
`n91-portal-p0-10-20261112`. Xem [hướng dẫn triển khai](deploy/proxy/README.md)
để cấu hình API, Nginx, phiên Portal và các nguồn dữ liệu.

## Build lại frontend và gói Linux

Từ thư mục repo:

    cd fe-api-staging
    npm ci
    npm run build -- --outDir ../deploy/.proxy-web-build --emptyOutDir
    cd ..
    python3 deploy/build_proxy_bundle.py --release-name n91-portal-p0-10-20261112 --output deploy/n91-portal-proxy-linux-new.tar.gz

npm run dev chạy Vite trong lúc phát triển. npm run build tạo file tĩnh cho bản triển khai. Frontend build gọi API qua /api và /api/v1 cùng origin.
Nếu build frontend trên Linux, dùng Node.js theo yêu cầu của Vite trong lockfile.
Khi dùng gói đã build, Proxy chỉ cần môi trường Python và dịch vụ phục vụ web.

## Cập nhật

Trong bản clone, chạy `git pull --ff-only` để lấy commit mới rồi triển khai gói
theo hướng dẫn của layout đang chạy. Bản cài bằng systemd đặt code tại
`/opt/n91-portal`, cấu hình tại `/etc/n91-portal` và dữ liệu tại
`/var/lib/n91-portal`. Bản dùng launcher `portal-local` nâng cấp thư mục
release mà launcher đang đọc. Sao lưu Business DB và chạy migration
`--migrate-only` nếu đang dùng schema 1. Cấu hình, credential và dữ liệu
vận hành được quản lý riêng trên Proxy.
