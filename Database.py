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

SELECT * FROM scans
WHERE sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
