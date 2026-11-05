SELECT filename, verdict, score, scan_date
FROM scans
ORDER BY scan_date DESC
LIMIT 5;

SELECT * FROM scans
WHERE filename LIKE '%exe%';

SELECT filename, sha256, score, tone
FROM scans
WHERE score >= 80
ORDER BY score DESC;

SELECT verdict, COUNT(*) AS total_files
FROM scans
GROUP BY verdict;

SELECT sha256, filename, COUNT(*) AS upload_count, MAX(scan_date) AS last_seen
FROM scans
GROUP BY sha256
HAVING COUNT(*) > 1
ORDER BY upload_count DESC;

SELECT DATE(scan_date) AS scan_day,
       COUNT(*) AS total_scans,
       SUM(CASE WHEN verdict = 'Malicious' THEN 1 ELSE 0 END) AS malicious_count
FROM scans
GROUP BY scan_day
ORDER BY scan_day DESC;

SELECT scan_id, filename, verdict, score, scan_date
FROM scans
WHERE filename LIKE '%.exe%' OR filename LIKE '%.bat%' OR filename LIKE '%.sh%';

SELECT * FROM scans
WHERE sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
