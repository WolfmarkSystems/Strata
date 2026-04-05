import React from 'react';

export default function GalleryView({ images }) {
  return (
    <div className="grid grid-cols-3 gap-2 p-2 overflow-auto h-full w-full">
      {images.map((img, i) => (
        <div key={i} className="aspect-square bg-muted rounded flex items-center justify-center border border-border">
          <img src={img.src} alt={img.alt || `Image ${i+1}`} className="max-w-full max-h-full object-contain rounded" />
        </div>
      ))}
    </div>
  );
}
