using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MS2Lib;

[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class MS2Archive : IMS2Archive {

    public MS2Archive(IMS2ArchiveCryptoRepository cryptoRepo) :
        this(cryptoRepo, Guid.NewGuid().ToString()) { }

    public MS2Archive(IMS2ArchiveCryptoRepository cryptoRepo, string name) {
        CryptoRepository = cryptoRepo ?? throw new ArgumentNullException(nameof(cryptoRepo));
        Name = name;
        Files = new ConcurrentDictionary<long, IMS2File>();
    }
    protected MemoryMappedFile MappedDataFile { get; set; }
    protected IMS2SizeHeader FileInfoHeaderSize { get; set; }
    protected IMS2SizeHeader FileDataHeaderSize { get; set; }
    protected ConcurrentDictionary<long, IMS2File> Files { get; }
    public IEnumerable<long> Keys => Files.Keys;
    public IEnumerable<IMS2File> Values => Files.Values;

    public IMS2File this[long key] {
        get => Files[key];
        set {
            if (TryGetValue(key, out IMS2File file)) {
                file.Dispose();
                Files[key] = value;
            }
        }
    }

    [ExcludeFromCodeCoverage]
    protected virtual string DebuggerDisplay
        => $"Files = {Files.Count}, Name = {MappedDataFile}";

    public IMS2ArchiveCryptoRepository CryptoRepository { get; }
    public string Name { get; }
    public int Count => Files.Count;
    public ReadOnlyDictionary<long, IMS2File> FileDictionary => new ReadOnlyDictionary<long, IMS2File>(Files);

    public bool ContainsKey(long key) {
        return Files.ContainsKey(key);
    }
    public bool TryGetValue(long key, out IMS2File value) {
        return Files.TryGetValue(key, out value);
    }
    public IEnumerator<IMS2File> GetEnumerator() {
        return Values.GetEnumerator();
    }
    public bool Add(IMS2File value) {
        if (value is null) {
            throw new ArgumentNullException(nameof(value));
        }

        return Files.TryAdd(value.Id, value);
    }

    public bool Remove(long key, bool disposeRemoved = true) {
        bool result = Files.Remove(key, out IMS2File file);
        if (disposeRemoved) {
            file?.Dispose();
        }

        return result;
    }

    public void Clear(bool disposeRemoved = true) {
        if (disposeRemoved) {
            foreach (IMS2File f in Values) {
                f.Dispose();
            }
        }

        Files.Clear();
    }

    #region Hidden interfaces
    IEnumerator IEnumerable.GetEnumerator() {
        return GetEnumerator();
    }
    #endregion

    protected virtual void Reset() {
        if (MappedDataFile != null) {
            MappedDataFile.Dispose();
            MappedDataFile = null;
        }

        FileInfoHeaderSize = null;
        FileDataHeaderSize = null;

        foreach (KeyValuePair<long, IMS2File> kvp in Files) {
            kvp.Value.Dispose();
        }

        Files.Clear();
    }

    #region LoadAsync
    public async Task LoadAsync(string headerFilePath, string dataFilePath) {
        if (IsDisposed) {
            throw new ObjectDisposedException(nameof(MS2Archive));
        }

        Reset();

        await using FileStream headerStream = File.OpenRead(headerFilePath);
        await using FileStream dataStream = File.OpenRead(dataFilePath);

        await LoadAsync(headerStream, dataStream).ConfigureAwait(false);
    }

    protected async Task LoadAsync(FileStream headerStream, FileStream dataStream) {
        MappedDataFile = MemoryMappedFile.CreateFromFile(dataStream, null, 0L, MemoryMappedFileAccess.Read, HandleInheritability.None, true);

        try {
            await InternalLoadAsync(headerStream).ConfigureAwait(false);
        } catch {
            Reset();
            throw;
        }
    }

    protected async Task InternalLoadAsync(FileStream headerStream) {
        using var br = new BinaryReader(headerStream, Encoding.ASCII, true);

        var cryptoMode = (MS2CryptoMode) br.ReadUInt32();
        if (CryptoRepository.CryptoMode != cryptoMode) {
            throw new BadMS2ArchiveException();
        }

        IMS2ArchiveHeaderCrypto archiveHeaderCrypto = CryptoRepository.GetArchiveHeaderCrypto();
        (IMS2SizeHeader header, IMS2SizeHeader data, long fileCount) = await archiveHeaderCrypto.ReadAsync(headerStream).ConfigureAwait(false);
        FileInfoHeaderSize = header;
        FileDataHeaderSize = data;

        await LoadFilesAsync(headerStream, fileCount).ConfigureAwait(false);
    }

    protected async virtual Task LoadFilesAsync(FileStream headerStream, long fileCount) {
        IMS2FileInfoCrypto fileInfoCrypto = CryptoRepository.GetFileInfoReaderCrypto();
        IMS2FileHeaderCrypto fileHeaderCrypto = CryptoRepository.GetFileHeaderCrypto();

        // TODO: are those always compressed?
        await using Stream fileInfoHeaderDecrypted = await CryptoRepository.GetDecryptionStreamAsync(headerStream, FileInfoHeaderSize, true).ConfigureAwait(false);
        await using Stream fileDataHeaderDecrypted = await CryptoRepository.GetDecryptionStreamAsync(headerStream, FileDataHeaderSize, true).ConfigureAwait(false);

        var reader = new StreamReader(fileInfoHeaderDecrypted);

        for (int i = 0; i < fileCount; i++) {
            IMS2FileInfo fileInfo = await fileInfoCrypto.ReadAsync(reader).ConfigureAwait(false);
            IMS2FileHeader fileHeader = await fileHeaderCrypto.ReadAsync(fileDataHeaderDecrypted).ConfigureAwait(false);
            var file = new MS2File(this, MappedDataFile, fileInfo, fileHeader, true);

            Add(file);
        }
    }
    #endregion

    #region SaveAsync
    public async Task SaveAsync(string headerFilePath, string dataFilePath) {
        if (IsDisposed) {
            throw new ObjectDisposedException(nameof(MS2Archive));
        }

        await using FileStream headerStream = File.OpenWrite(headerFilePath);
        await using FileStream dataStream = File.OpenWrite(dataFilePath);

        headerStream.SetLength(0L);
        dataStream.SetLength(0L);

        await SaveAsync(headerStream, dataStream);
    }

    public async Task SaveConcurrentlyAsync(string headerFilePath, string dataFilePath) {
        if (IsDisposed) {
            throw new ObjectDisposedException(nameof(MS2Archive));
        }

        await using FileStream headerStream = File.OpenWrite(headerFilePath);

        headerStream.SetLength(0L);

        await SaveConcurrentAsync(headerStream, dataFilePath);
    }

    protected async Task SaveAsync(FileStream headerStream, FileStream dataStream) {
        IMS2ArchiveHeaderCrypto archiveHeaderCrypto = CryptoRepository.GetArchiveHeaderCrypto();
        IMS2FileInfoCrypto fileInfoCrypto = CryptoRepository.GetFileInfoReaderCrypto();
        IMS2FileHeaderCrypto fileHeaderCrypto = CryptoRepository.GetFileHeaderCrypto();

        using var fileInfoMemoryStream = new MemoryStream();
        using var fileHeaderMemoryStream = new MemoryStream();

        long fileCount = Files.Count;
        long offset = 0;

        await using (var fileInfoWriter = new StreamWriter(fileInfoMemoryStream, Encoding.ASCII, 1 << 10, true)) {
            fileInfoWriter.NewLine = "\r\n";
            foreach (IMS2File file in Files.Values.OrderBy(f => f.Id)) {
                (Stream fileStream, IMS2SizeHeader fileSize) = await file.GetStreamForArchivingAsync().ConfigureAwait(false);

                await fileStream.CopyToAsync(dataStream).ConfigureAwait(false);

                await fileInfoCrypto.WriteAsync(fileInfoWriter, file.Info).ConfigureAwait(false);

                IMS2FileHeader newFileHeader = new MS2FileHeader(fileSize, file.Header.Id, offset, file.Header.CompressionType);
                await fileHeaderCrypto.WriteAsync(fileHeaderMemoryStream, newFileHeader).ConfigureAwait(false);

                offset += fileSize.EncodedSize;
            }
        }

        fileInfoMemoryStream.Position = 0;
        fileHeaderMemoryStream.Position = 0;

        // TODO: are those always compressed?
        (Stream fileInfoEncryptedStream, IMS2SizeHeader fileInfoSize) = await CryptoRepository.GetEncryptionStreamAsync(fileInfoMemoryStream, fileInfoMemoryStream.Length, true).ConfigureAwait(false);
        (Stream fileHeaderEncryptedStream, IMS2SizeHeader fileHeaderSize) = await CryptoRepository.GetEncryptionStreamAsync(fileHeaderMemoryStream, fileHeaderMemoryStream.Length, true).ConfigureAwait(false);

        // write header stream (m2h)
        await using var headerWriter = new BinaryWriter(headerStream, Encoding.ASCII, true);
        headerWriter.Write((uint) CryptoRepository.CryptoMode);

        await archiveHeaderCrypto.WriteAsync(headerStream, fileInfoSize, fileHeaderSize, fileCount).ConfigureAwait(false);

        await using (fileInfoEncryptedStream)
        await using (fileHeaderEncryptedStream) {
            await fileInfoEncryptedStream.CopyToAsync(headerStream).ConfigureAwait(false);
            await fileHeaderEncryptedStream.CopyToAsync(headerStream).ConfigureAwait(false);
        }
    }

    protected async Task SaveConcurrentAsync(FileStream headerStream, string dataFilePath) {
        FileStream dataStream = File.Open(dataFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        dataStream.SetLength(0L);

        IMS2ArchiveHeaderCrypto archiveHeaderCrypto = CryptoRepository.GetArchiveHeaderCrypto();
        IMS2FileInfoCrypto fileInfoCrypto = CryptoRepository.GetFileInfoReaderCrypto();
        IMS2FileHeaderCrypto fileHeaderCrypto = CryptoRepository.GetFileHeaderCrypto();

        using var fileHeaderMemoryStream = new MemoryStream();

        IMS2File[] files = Files.Values.OrderBy(f => f.Id).ToArray();
        long fileCount = files.Length;

        // prepare for writing (encrypt if necessary) load everything in memory
        Task<(Stream stream, IMS2SizeHeader size)>[] archivingTasks = files.Select(async file => {
            await Task.Yield();

            (Stream stream, IMS2SizeHeader size) = await file.GetStreamForArchivingAsync().ConfigureAwait(false);

            if (stream is MemoryStream ms) {
                return ((Stream) ms, size);
            }
            if (stream is KeepOpenStreamProxy {Stream: MemoryStream} proxy) {
                return (proxy, size);
            }
            byte[] buffer = new byte[size.EncodedSize];
            var newMs = new MemoryStream(buffer);
            await stream.CopyToAsync(newMs).ConfigureAwait(false);
            stream.Dispose();
            newMs.Position = 0;

            return (newMs, size);
        }).ToArray();

        await Task.WhenAll(archivingTasks).ConfigureAwait(false);

        long offset = 0;
        var streams = new Stream[fileCount];
        var fileHeaders = new IMS2FileHeader[fileCount];

        // Use StreamWriter over MemoryStream for cross-platform consistency
        using var fileInfoMemoryStream = new MemoryStream();
        await using (var fileInfoWriter = new StreamWriter(fileInfoMemoryStream, Encoding.ASCII, 1 << 10, true)) {
            fileInfoWriter.NewLine = "\r\n";
            for (int i = 0; i < fileCount; i++) {
                (Stream stream, IMS2SizeHeader size) = await archivingTasks[i].ConfigureAwait(false);
                IMS2File file = files[i];

                streams[i] = stream;

                await fileInfoCrypto.WriteAsync(fileInfoWriter, file.Info).ConfigureAwait(false);

                IMS2FileHeader newFileHeader = new MS2FileHeader(size, file.Header.Id, offset, file.Header.CompressionType);
                fileHeaders[i] = newFileHeader;

                await fileHeaderCrypto.WriteAsync(fileHeaderMemoryStream, newFileHeader).ConfigureAwait(false);

                offset += size.EncodedSize;
            }
            await fileInfoWriter.FlushAsync();
        }
        fileInfoMemoryStream.Position = 0;
        fileHeaderMemoryStream.Position = 0;

        // TODO: are those always compressed?
        (Stream fileInfoEncryptedStream, IMS2SizeHeader fileInfoSize) = await CryptoRepository.GetEncryptionStreamAsync(fileInfoMemoryStream, fileInfoMemoryStream.Length, true).ConfigureAwait(false);
        (Stream fileHeaderEncryptedStream, IMS2SizeHeader fileHeaderSize) = await CryptoRepository.GetEncryptionStreamAsync(fileHeaderMemoryStream, fileHeaderMemoryStream.Length, true).ConfigureAwait(false);

        // write data file
        using (var mmf = MemoryMappedFile.CreateFromFile(dataStream, null, offset, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, false)) {
            Task[] dataWritingTasks = fileHeaders.Select(async (fileHeader, i) => {
                await Task.Yield();

                await using Stream stream = streams[i];

                await using MemoryMappedViewStream mmfStream = mmf.CreateViewStream(fileHeader.Offset, fileHeader.Size.EncodedSize, MemoryMappedFileAccess.Write);
                await stream.CopyToAsync(mmfStream).ConfigureAwait(false);
            }).ToArray();

            await Task.WhenAll(dataWritingTasks).ConfigureAwait(false);
        }

        // write header stream (m2h)
        await using var headerWriter = new BinaryWriter(headerStream, Encoding.ASCII, true);
        headerWriter.Write((uint) CryptoRepository.CryptoMode);

        await archiveHeaderCrypto.WriteAsync(headerStream, fileInfoSize, fileHeaderSize, fileCount).ConfigureAwait(false);

        await using (fileInfoEncryptedStream)
        await using (fileHeaderEncryptedStream) {
            await fileInfoEncryptedStream.CopyToAsync(headerStream).ConfigureAwait(false);
            await fileHeaderEncryptedStream.CopyToAsync(headerStream).ConfigureAwait(false);
        }
    }
    #endregion

    #region IDisposable interface
    private bool IsDisposed;

    protected virtual void Dispose(bool disposing) {
        if (!IsDisposed) {
            if (disposing) {
                // managed
                Reset();
            }

            // unmanaged

            IsDisposed = true;
        }
    }

    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    #endregion

    #region static helpers
    public static IMS2Archive GetArchiveMS2F() {
        return new MS2Archive(Repositories.Repos[MS2CryptoMode.MS2F]);
    }
    public static IMS2Archive GetArchiveNS2F() {
        return new MS2Archive(Repositories.Repos[MS2CryptoMode.NS2F]);
    }

    public static async Task<IMS2Archive> GetAndLoadArchiveAsync(string headerFilePath, string dataFilePath) {
        await using FileStream headerStream = File.OpenRead(headerFilePath);
        await using FileStream dataStream = File.OpenRead(dataFilePath);

        if (headerStream.Length < 4) {
            throw new BadMS2ArchiveException("Given file is too small.");
        }

        MS2CryptoMode cryptoMode;
        using (var br = new BinaryReader(headerStream, Encoding.ASCII, true)) {
            cryptoMode = (MS2CryptoMode) br.ReadInt32();
        }

        if (!Repositories.Repos.ContainsKey(cryptoMode)) {
            throw new BadMS2ArchiveException("Unknown file format or unable to automatically determine the file format.");
        }

        headerStream.Position = 0;
        var archive = new MS2Archive(Repositories.Repos[cryptoMode]);
        await archive.LoadAsync(headerStream, dataStream);

        return archive;
    }
    #endregion
}
