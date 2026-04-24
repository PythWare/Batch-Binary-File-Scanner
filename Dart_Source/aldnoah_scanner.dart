import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:typed_data';

const int countReportBatch = 5000;
const Duration countProgressInterval = Duration(milliseconds: 500);
const int workerProgressFileBatch = 256;
const int workerProgressByteBatch = 128 * 1024 * 1024;
const Duration workerProgressInterval = Duration(milliseconds: 400);
const int mmapThreshold = 1 * 1024 * 1024;
const int maxAutoWorkers = 8;

const int genericRead = 0x80000000;
const int fileShareRead = 0x00000001;
const int fileShareWrite = 0x00000002;
const int fileShareDelete = 0x00000004;
const int openExisting = 3;
const int fileAttributeNormal = 0x00000080;
const int fileFlagSequentialScan = 0x08000000;
const int pageReadonly = 0x02;
const int fileMapRead = 0x0004;
const int invalidHandleValue = -1;

final ffi.DynamicLibrary _msvcrt = ffi.DynamicLibrary.open('msvcrt.dll');
final ffi.DynamicLibrary _kernel32 = ffi.DynamicLibrary.open('kernel32.dll');

typedef _MallocNative = ffi.Pointer<ffi.Void> Function(ffi.Size byteCount);
typedef _MallocDart = ffi.Pointer<ffi.Void> Function(int byteCount);
typedef _FreeNative = ffi.Void Function(ffi.Pointer<ffi.Void> pointer);
typedef _FreeDart = void Function(ffi.Pointer<ffi.Void> pointer);

typedef _CreateFileWNative = ffi.IntPtr Function(
  ffi.Pointer<ffi.Uint16> fileName,
  ffi.Uint32 desiredAccess,
  ffi.Uint32 shareMode,
  ffi.Pointer<ffi.Void> securityAttributes,
  ffi.Uint32 creationDisposition,
  ffi.Uint32 flagsAndAttributes,
  ffi.IntPtr templateFile,
);
typedef _CreateFileWDart = int Function(
  ffi.Pointer<ffi.Uint16> fileName,
  int desiredAccess,
  int shareMode,
  ffi.Pointer<ffi.Void> securityAttributes,
  int creationDisposition,
  int flagsAndAttributes,
  int templateFile,
);

typedef _CreateFileMappingWNative = ffi.IntPtr Function(
  ffi.IntPtr fileHandle,
  ffi.Pointer<ffi.Void> securityAttributes,
  ffi.Uint32 protect,
  ffi.Uint32 maximumSizeHigh,
  ffi.Uint32 maximumSizeLow,
  ffi.Pointer<ffi.Uint16> name,
);
typedef _CreateFileMappingWDart = int Function(
  int fileHandle,
  ffi.Pointer<ffi.Void> securityAttributes,
  int protect,
  int maximumSizeHigh,
  int maximumSizeLow,
  ffi.Pointer<ffi.Uint16> name,
);

typedef _MapViewOfFileNative = ffi.Pointer<ffi.Uint8> Function(
  ffi.IntPtr mappingHandle,
  ffi.Uint32 desiredAccess,
  ffi.Uint32 fileOffsetHigh,
  ffi.Uint32 fileOffsetLow,
  ffi.IntPtr numberOfBytesToMap,
);
typedef _MapViewOfFileDart = ffi.Pointer<ffi.Uint8> Function(
  int mappingHandle,
  int desiredAccess,
  int fileOffsetHigh,
  int fileOffsetLow,
  int numberOfBytesToMap,
);

typedef _UnmapViewOfFileNative = ffi.Int32 Function(ffi.Pointer<ffi.Void> baseAddress);
typedef _UnmapViewOfFileDart = int Function(ffi.Pointer<ffi.Void> baseAddress);

typedef _CloseHandleNative = ffi.Int32 Function(ffi.IntPtr objectHandle);
typedef _CloseHandleDart = int Function(int objectHandle);

final _MallocDart _malloc = _msvcrt.lookupFunction<_MallocNative, _MallocDart>('malloc');
final _FreeDart _free = _msvcrt.lookupFunction<_FreeNative, _FreeDart>('free');
final _CreateFileWDart _createFileW =
    _kernel32.lookupFunction<_CreateFileWNative, _CreateFileWDart>('CreateFileW');
final _CreateFileMappingWDart _createFileMappingW = _kernel32.lookupFunction<
    _CreateFileMappingWNative,
    _CreateFileMappingWDart>('CreateFileMappingW');
final _MapViewOfFileDart _mapViewOfFile =
    _kernel32.lookupFunction<_MapViewOfFileNative, _MapViewOfFileDart>('MapViewOfFile');
final _UnmapViewOfFileDart _unmapViewOfFile =
    _kernel32.lookupFunction<_UnmapViewOfFileNative, _UnmapViewOfFileDart>('UnmapViewOfFile');
final _CloseHandleDart _closeHandle =
    _kernel32.lookupFunction<_CloseHandleNative, _CloseHandleDart>('CloseHandle');

class ScanRequest {
  final String rootDir;
  final String patternHex;
  final String patternDisplay;
  final String mode;
  final String encoding;
  final String compression;
  final int zlibLevel;
  final String resultsPath;

  ScanRequest({
    required this.rootDir,
    required this.patternHex,
    required this.patternDisplay,
    required this.mode,
    required this.encoding,
    required this.compression,
    required this.zlibLevel,
    required this.resultsPath,
  });

  factory ScanRequest.fromJson(Map<String, dynamic> json) {
    final rootDir = (json['root_dir'] ?? '').toString();
    final patternHex = (json['pattern_hex'] ?? '').toString();
    final patternDisplay = (json['pattern_display'] ?? '').toString();
    final mode = (json['mode'] ?? 'hex').toString();
    final encoding = (json['encoding'] ?? 'utf-8').toString();
    final compression = (json['compression'] ?? 'none').toString();
    final zlibLevel = int.tryParse((json['zlib_level'] ?? '6').toString()) ?? 6;
    final resultsPath = (json['results_path'] ?? 'scan_results.txt').toString();

    if (rootDir.isEmpty) {
      throw ArgumentError('root_dir is required.');
    }
    if (patternHex.isEmpty) {
      throw ArgumentError('pattern_hex is required.');
    }

    return ScanRequest(
      rootDir: rootDir,
      patternHex: patternHex,
      patternDisplay: patternDisplay,
      mode: mode,
      encoding: encoding,
      compression: compression,
      zlibLevel: zlibLevel,
      resultsPath: resultsPath,
    );
  }

  factory ScanRequest.fromLegacyArgs(List<String> args) {
    return ScanRequest(
      rootDir: args[0],
      patternHex: args[1],
      patternDisplay: args[1],
      mode: 'hex',
      encoding: 'utf-8',
      compression: 'none',
      zlibLevel: 6,
      resultsPath: 'scan_results.txt',
    );
  }
}

class PatternData {
  final Uint8List pattern;
  final Uint8List mask;
  final bool hasWild;

  PatternData(this.pattern, this.mask, this.hasWild);
}

class ScanTarget {
  final int index;
  final String path;
  final int size;

  const ScanTarget({
    required this.index,
    required this.path,
    required this.size,
  });

  Map<String, Object> toMessage() {
    return {
      'index': index,
      'path': path,
      'size': size,
    };
  }

  factory ScanTarget.fromMessage(Map<dynamic, dynamic> message) {
    return ScanTarget(
      index: message['index'] as int,
      path: message['path'] as String,
      size: message['size'] as int,
    );
  }
}

class MappedBytesView {
  final int fileHandle;
  final int mappingHandle;
  final ffi.Pointer<ffi.Uint8> viewPointer;
  final int length;

  MappedBytesView._({
    required this.fileHandle,
    required this.mappingHandle,
    required this.viewPointer,
    required this.length,
  });

  Uint8List get bytes => viewPointer.asTypedList(length);

  static MappedBytesView? tryOpen(String path, int length) {
    if (!Platform.isWindows || length <= 0) {
      return null;
    }

    final nativePath = _toNativeUtf16(path);
    try {
      final fileHandle = _createFileW(
        nativePath,
        genericRead,
        fileShareRead | fileShareWrite | fileShareDelete,
        ffi.nullptr,
        openExisting,
        fileAttributeNormal | fileFlagSequentialScan,
        0,
      );

      if (fileHandle == invalidHandleValue) {
        return null;
      }

      final mappingHandle = _createFileMappingW(
        fileHandle,
        ffi.nullptr,
        pageReadonly,
        0,
        0,
        ffi.nullptr.cast<ffi.Uint16>(),
      );

      if (mappingHandle == 0) {
        _closeHandle(fileHandle);
        return null;
      }

      final viewPointer = _mapViewOfFile(
        mappingHandle,
        fileMapRead,
        0,
        0,
        0,
      );

      if (viewPointer.address == 0) {
        _closeHandle(mappingHandle);
        _closeHandle(fileHandle);
        return null;
      }

      return MappedBytesView._(
        fileHandle: fileHandle,
        mappingHandle: mappingHandle,
        viewPointer: viewPointer,
        length: length,
      );
    } finally {
      _free(nativePath.cast<ffi.Void>());
    }
  }

  void close() {
    if (viewPointer.address != 0) {
      _unmapViewOfFile(viewPointer.cast<ffi.Void>());
    }
    if (mappingHandle != 0) {
      _closeHandle(mappingHandle);
    }
    if (fileHandle != 0 && fileHandle != invalidHandleValue) {
      _closeHandle(fileHandle);
    }
  }
}

ffi.Pointer<ffi.Uint16> _toNativeUtf16(String value) {
  final units = value.codeUnits;
  final pointer = _malloc((units.length + 1) * ffi.sizeOf<ffi.Uint16>());
  if (pointer.address == 0) {
    throw StateError('Failed to allocate native string buffer.');
  }

  final typedPointer = pointer.cast<ffi.Uint16>();
  final nativeUnits = typedPointer.asTypedList(units.length + 1);
  nativeUnits.setRange(0, units.length, units);
  nativeUnits[units.length] = 0;
  return typedPointer;
}

String normalizeHexPattern(String hex) {
  final cleaned = hex.replaceAll(RegExp(r'[\s_]'), '').toUpperCase();
  if (cleaned.isEmpty) {
    throw ArgumentError('Pattern cannot be empty.');
  }
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string length must be even.');
  }

  for (int i = 0; i < cleaned.length; i += 2) {
    final pair = cleaned.substring(i, i + 2);
    if (pair == '??') {
      continue;
    }
    int.parse(pair, radix: 16);
  }

  return cleaned;
}

PatternData parsePattern(String hex) {
  final normalized = normalizeHexPattern(hex);
  final pattern = <int>[];
  final mask = <int>[];
  var hasWild = false;

  for (int i = 0; i < normalized.length; i += 2) {
    final pair = normalized.substring(i, i + 2);
    if (pair == '??') {
      pattern.add(0);
      mask.add(0);
      hasWild = true;
    } else {
      pattern.add(int.parse(pair, radix: 16));
      mask.add(1);
    }
  }

  return PatternData(
    Uint8List.fromList(pattern),
    Uint8List.fromList(mask),
    hasWild,
  );
}

PatternData buildSearchPattern(ScanRequest request) {
  final basePattern = parsePattern(request.patternHex);
  if (basePattern.pattern.isEmpty) {
    throw ArgumentError('Pattern cannot be empty.');
  }

  if (basePattern.hasWild && !basePattern.mask.contains(1)) {
    throw ArgumentError('Pattern is all wildcards, refusing to match everything.');
  }

  if (request.compression != 'zlib') {
    return basePattern;
  }

  if (basePattern.hasWild) {
    throw ArgumentError('Wildcards are only supported with uncompressed hex search.');
  }

  final level = request.zlibLevel.clamp(1, 9);
  final compressed = ZLibCodec(level: level).encode(basePattern.pattern);
  return PatternData(
    Uint8List.fromList(compressed),
    Uint8List.fromList(List<int>.filled(compressed.length, 1)),
    false,
  );
}

List<int> buildShiftTable(Uint8List pattern) {
  final shiftTable = List<int>.filled(256, pattern.length);
  if (pattern.length <= 1) {
    return shiftTable;
  }

  for (int i = 0; i < pattern.length - 1; i++) {
    shiftTable[pattern[i]] = pattern.length - 1 - i;
  }

  return shiftTable;
}

int indexOfPattern(
  Uint8List data,
  Uint8List pattern,
  int start,
  List<int> shiftTable,
) {
  final patternLength = pattern.length;
  final lastValidStart = data.length - patternLength;
  if (patternLength == 0 || start > lastValidStart) {
    return -1;
  }

  if (patternLength == 1) {
    return data.indexOf(pattern[0], start);
  }

  var cursor = start;
  while (cursor <= lastValidStart) {
    var patternIndex = patternLength - 1;
    while (patternIndex >= 0 &&
        data[cursor + patternIndex] == pattern[patternIndex]) {
      patternIndex--;
    }

    if (patternIndex < 0) {
      return cursor;
    }

    final tailByte = data[cursor + patternLength - 1];
    cursor += shiftTable[tailByte];
  }

  return -1;
}

List<int> findExact(Uint8List data, Uint8List pattern) {
  final hits = <int>[];
  final patternLength = pattern.length;
  final dataLength = data.length;
  if (patternLength == 0 || dataLength < patternLength) {
    return hits;
  }

  if (patternLength == 1) {
    var pos = 0;
    while (true) {
      final idx = data.indexOf(pattern[0], pos);
      if (idx == -1) {
        break;
      }
      hits.add(idx);
      pos = idx + 1;
    }
    return hits;
  }

  final shiftTable = buildShiftTable(pattern);
  var cursor = 0;
  final lastValidStart = dataLength - patternLength;

  while (cursor <= lastValidStart) {
    var patternIndex = patternLength - 1;
    while (patternIndex >= 0 &&
        data[cursor + patternIndex] == pattern[patternIndex]) {
      patternIndex--;
    }

    if (patternIndex < 0) {
      hits.add(cursor);
      cursor += 1;
      continue;
    }

    final tailByte = data[cursor + patternLength - 1];
    cursor += shiftTable[tailByte];
  }

  return hits;
}

List<int> findBestAnchor(Uint8List pattern, Uint8List mask) {
  var bestStart = 0;
  var bestLen = 0;
  var curStart = 0;
  var curLen = 0;

  for (int i = 0; i < mask.length; i++) {
    if (mask[i] == 1) {
      if (curLen == 0) {
        curStart = i;
      }
      curLen++;

      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curLen = 0;
    }
  }

  return [bestStart, bestLen];
}

List<int> findWildcard(Uint8List data, PatternData patternData) {
  final hits = <int>[];
  final patternLength = patternData.pattern.length;
  final dataLength = data.length;

  if (patternLength == 0 || dataLength < patternLength) {
    return hits;
  }

  final anchorInfo = findBestAnchor(patternData.pattern, patternData.mask);
  final anchorStart = anchorInfo[0];
  final anchorLength = anchorInfo[1];

  if (anchorLength == 0) {
    return hits;
  }

  final anchor = Uint8List.fromList(
    patternData.pattern.sublist(anchorStart, anchorStart + anchorLength),
  );
  final anchorShiftTable = buildShiftTable(anchor);

  var pos = 0;
  while (true) {
    final idx = indexOfPattern(data, anchor, pos, anchorShiftTable);
    if (idx == -1) {
      break;
    }

    final candidate = idx - anchorStart;
    if (candidate >= 0 && candidate + patternLength <= dataLength) {
      var matched = true;
      for (int i = 0; i < patternLength; i++) {
        if (patternData.mask[i] == 1 &&
            data[candidate + i] != patternData.pattern[i]) {
          matched = false;
          break;
        }
      }

      if (matched) {
        hits.add(candidate);
      }
    }

    pos = idx + 1;
  }

  return hits;
}

List<int> scanBytes(Uint8List data, PatternData patternData) {
  if (patternData.hasWild) {
    return findWildcard(data, patternData);
  }
  return findExact(data, patternData.pattern);
}

List<int> scanTargetFile(ScanTarget target, PatternData patternData) {
  if (target.size <= 0 || target.size < patternData.pattern.length) {
    return const <int>[];
  }

  if (Platform.isWindows && target.size >= mmapThreshold) {
    final mappedView = MappedBytesView.tryOpen(target.path, target.size);
    if (mappedView != null) {
      try {
        return scanBytes(mappedView.bytes, patternData);
      } finally {
        mappedView.close();
      }
    }
  }

  final fileBytes = File(target.path).readAsBytesSync();
  return scanBytes(Uint8List.fromList(fileBytes), patternData);
}

Future<void> emitJson(Map<String, Object?> payload) async {
  stdout.writeln(jsonEncode(payload));
  await stdout.flush();
}

Future<ScanRequest> loadRequest(List<String> args) async {
  if (args.isNotEmpty && args.first == '--json') {
    final raw = await stdin.transform(utf8.decoder).join();
    if (raw.trim().isEmpty) {
      throw ArgumentError('Scanner request was empty.');
    }

    final decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic>) {
      throw ArgumentError('Scanner request must be a JSON object.');
    }

    return ScanRequest.fromJson(decoded);
  }

  if (args.length >= 2) {
    return ScanRequest.fromLegacyArgs(args);
  }

  throw ArgumentError('Expected --json request on stdin or legacy args.');
}

Stream<FileSystemEntity> safeEntityStream(String rootDir) {
  return Directory(rootDir).list(
    recursive: true,
    followLinks: false,
  ).handleError(
    (_) {},
    test: (error) => error is FileSystemException,
  );
}

Future<List<ScanTarget>> enumerateTargets(String rootDir, int minFileSize) async {
  final targets = <ScanTarget>[];
  final countWatch = Stopwatch()..start();

  await emitJson({'type': 'counting', 'files_counted': 0});

  await for (final entity in safeEntityStream(rootDir)) {
    if (entity is! File) {
      continue;
    }

    int size;
    try {
      size = await entity.length();
    } on FileSystemException {
      continue;
    }

    if (size < minFileSize || size == 0) {
      continue;
    }

    targets.add(
      ScanTarget(
        index: targets.length,
        path: entity.path,
        size: size,
      ),
    );

    final shouldReport = targets.length == 1 ||
        targets.length % countReportBatch == 0 ||
        countWatch.elapsed >= countProgressInterval;

    if (shouldReport) {
      await emitJson({'type': 'counting', 'files_counted': targets.length});
      countWatch
        ..reset()
        ..start();
    }
  }

  await emitJson({'type': 'counting', 'files_counted': targets.length});
  return targets;
}

int determineWorkerCount(int fileCount, int totalBytes) {
  final override = int.tryParse(Platform.environment['ALDNOAH_SCANNER_WORKERS'] ?? '');
  if (override != null && override > 0) {
    return math.max(1, math.min(override, fileCount == 0 ? 1 : fileCount));
  }

  if (fileCount == 0) {
    return 1;
  }

  final processors = math.max(1, Platform.numberOfProcessors);
  var workers = math.max(1, math.min(maxAutoWorkers, processors - 1));

  if (fileCount <= 4 || totalBytes < 32 * 1024 * 1024) {
    workers = 1;
  } else if (fileCount < 200) {
    if (totalBytes >= 1024 * 1024 * 1024) {
      workers = math.min(workers, 4);
    } else if (totalBytes >= 128 * 1024 * 1024) {
      workers = math.min(workers, 2);
    } else {
      workers = 1;
    }
  } else if (fileCount < 2000 || totalBytes < 256 * 1024 * 1024) {
    workers = math.min(workers, 2);
  } else if (fileCount < 10000 || totalBytes < 1024 * 1024 * 1024) {
    workers = math.min(workers, 4);
  }

  return math.max(1, math.min(workers, fileCount));
}

List<List<ScanTarget>> partitionTargets(List<ScanTarget> targets, int workerCount) {
  final chunks = List.generate(workerCount, (_) => <ScanTarget>[]);
  final chunkBytes = List<int>.filled(workerCount, 0);
  final sortedTargets = List<ScanTarget>.from(targets)
    ..sort((a, b) => b.size.compareTo(a.size));

  for (final target in sortedTargets) {
    var bestIndex = 0;
    var lowestBytes = chunkBytes[0];

    for (int i = 1; i < chunkBytes.length; i++) {
      if (chunkBytes[i] < lowestBytes) {
        lowestBytes = chunkBytes[i];
        bestIndex = i;
      }
    }

    chunks[bestIndex].add(target);
    chunkBytes[bestIndex] += target.size;
  }

  return chunks.where((chunk) => chunk.isNotEmpty).toList();
}

Future<void> writeHeader(
  IOSink sink,
  ScanRequest request,
  PatternData searchPattern,
  int totalFiles,
  int totalBytes,
  int workerCount,
) async {
  sink.writeln('Search root: ${request.rootDir}');
  sink.writeln('Mode: ${request.mode}');
  if (request.mode == 'text') {
    sink.writeln('Text pattern: ${request.patternDisplay}');
    sink.writeln('Encoding: ${request.encoding}');
  } else {
    sink.writeln('Hex pattern: ${request.patternDisplay}');
  }
  sink.writeln('Compression: ${request.compression}');
  if (request.compression == 'zlib') {
    sink.writeln('Zlib level: ${request.zlibLevel.clamp(1, 9)}');
  }
  sink.writeln(
    'Search bytes (hex): ${searchPattern.pattern.map((b) => b.toRadixString(16).padLeft(2, '0')).join().toUpperCase()}',
  );
  sink.writeln('Files scheduled: $totalFiles');
  sink.writeln('Bytes scheduled: $totalBytes');
  sink.writeln('Parallel workers: $workerCount');
  sink.writeln();
}

void scanWorkerMain(List<dynamic> args) {
  final sendPort = args[0] as SendPort;

  try {
    final targetMessages = (args[1] as List<dynamic>).cast<Map<dynamic, dynamic>>();
    final targets = targetMessages.map(ScanTarget.fromMessage).toList(growable: false);
    final pattern = Uint8List.fromList((args[2] as List<dynamic>).cast<int>());
    final mask = Uint8List.fromList((args[3] as List<dynamic>).cast<int>());
    final hasWild = args[4] as bool;
    final patternData = PatternData(pattern, mask, hasWild);

    var pendingFiles = 0;
    var pendingHits = 0;
    var pendingBytes = 0;
    var lastFile = '';
    final progressWatch = Stopwatch()..start();

    void flushProgress() {
      if (pendingFiles == 0 && pendingHits == 0 && pendingBytes == 0) {
        return;
      }

      sendPort.send({
        'type': 'worker_progress',
        'files_scanned_delta': pendingFiles,
        'hits_delta': pendingHits,
        'bytes_scanned_delta': pendingBytes,
        'current_file': lastFile,
      });

      pendingFiles = 0;
      pendingHits = 0;
      pendingBytes = 0;
      progressWatch
        ..reset()
        ..start();
    }

    for (final target in targets) {
      List<int> offsets = const <int>[];
      try {
        offsets = scanTargetFile(target, patternData);
      } catch (_) {
        offsets = const <int>[];
      }

      if (offsets.isNotEmpty) {
        sendPort.send({
          'type': 'worker_hit',
          'index': target.index,
          'file': target.path,
          'offsets': offsets,
        });
      }

      pendingFiles += 1;
      pendingHits += offsets.length;
      pendingBytes += target.size;
      lastFile = target.path;

      final shouldReport = pendingFiles >= workerProgressFileBatch ||
          pendingBytes >= workerProgressByteBatch ||
          progressWatch.elapsed >= workerProgressInterval;

      if (shouldReport) {
        flushProgress();
      }
    }

    flushProgress();
    sendPort.send({'type': 'worker_done'});
  } catch (error) {
    sendPort.send({
      'type': 'worker_error',
      'message': error.toString(),
    });
  }
}

Future<void> runScan(ScanRequest request) async {
  final rootDirectory = Directory(request.rootDir);
  if (!await rootDirectory.exists()) {
    throw FileSystemException('Directory does not exist.', request.rootDir);
  }

  final searchPattern = buildSearchPattern(request);
  final resultsFile = File(request.resultsPath);
  await resultsFile.parent.create(recursive: true);

  final targets = await enumerateTargets(request.rootDir, searchPattern.pattern.length);
  final totalFiles = targets.length;
  final totalBytes = targets.fold<int>(0, (sum, target) => sum + target.size);
  final workerCount = determineWorkerCount(totalFiles, totalBytes);

  final sink = resultsFile.openWrite(mode: FileMode.writeOnly, encoding: utf8);
  final isolates = <Isolate>[];

  try {
    await writeHeader(
      sink,
      request,
      searchPattern,
      totalFiles,
      totalBytes,
      workerCount,
    );

    await emitJson({
      'type': 'start',
      'total_files': totalFiles,
      'total_bytes': totalBytes,
      'worker_count': workerCount,
      'results_path': resultsFile.path,
    });

    if (totalFiles == 0) {
      sink.writeln('---');
      sink.writeln('Files scanned: 0, total hits: 0');
      await emitJson({
        'type': 'done',
        'files_scanned': 0,
        'total_files': 0,
        'hits': 0,
        'percent': 100.0,
        'results_path': resultsFile.path,
      });
      return;
    }

    final chunks = partitionTargets(targets, workerCount);
    final receivePort = ReceivePort();
    var workersRemaining = chunks.length;
    var filesScanned = 0;
    var totalHits = 0;
    var bytesScanned = 0;
    var currentFile = '';

    for (final chunk in chunks) {
      final isolate = await Isolate.spawn(
        scanWorkerMain,
        [
          receivePort.sendPort,
          chunk.map((target) => target.toMessage()).toList(growable: false),
          searchPattern.pattern.toList(growable: false),
          searchPattern.mask.toList(growable: false),
          searchPattern.hasWild,
        ],
      );
      isolates.add(isolate);
    }

    scanLoop:
    await for (final rawMessage in receivePort) {
      if (rawMessage is! Map) {
        continue;
      }

      final message = rawMessage.cast<dynamic, dynamic>();
      final type = message['type'];

      if (type == 'worker_hit') {
        sink.writeln('FILE: ${message['file']}');
        for (final offset in (message['offsets'] as List<dynamic>).cast<int>()) {
          sink.writeln('  offset: 0x${offset.toRadixString(16).toUpperCase()} ($offset decimal)');
        }
        sink.writeln();
        continue;
      }

      if (type == 'worker_progress') {
        filesScanned += message['files_scanned_delta'] as int;
        totalHits += message['hits_delta'] as int;
        bytesScanned += message['bytes_scanned_delta'] as int;
        currentFile = (message['current_file'] ?? '').toString();

        final percent = totalBytes == 0 ? 100.0 : (bytesScanned * 100.0) / totalBytes;
        await emitJson({
          'type': 'progress',
          'files_scanned': filesScanned,
          'total_files': totalFiles,
          'hits': totalHits,
          'percent': percent,
          'current_file': currentFile,
        });
        continue;
      }

      if (type == 'worker_error') {
        throw StateError((message['message'] ?? 'Worker isolate failed.').toString());
      }

      if (type == 'worker_done') {
        workersRemaining -= 1;
        if (workersRemaining <= 0) {
          receivePort.close();
          break scanLoop;
        }
      }
    }

    sink.writeln('---');
    sink.writeln('Files scanned: $filesScanned, total hits: $totalHits');

    await emitJson({
      'type': 'done',
      'files_scanned': filesScanned,
      'total_files': totalFiles,
      'hits': totalHits,
      'percent': 100.0,
      'results_path': resultsFile.path,
    });
  } finally {
    for (final isolate in isolates) {
      isolate.kill(priority: Isolate.immediate);
    }
    await sink.close();
  }
}

Future<void> main(List<String> args) async {
  try {
    final request = await loadRequest(args);
    await runScan(request);
  } catch (error) {
    await emitJson({
      'type': 'error',
      'message': error.toString(),
    });
    exitCode = 1;
  }
}
