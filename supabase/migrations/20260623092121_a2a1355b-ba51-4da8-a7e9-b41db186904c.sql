
CREATE TABLE public.category_images (
  cat TEXT PRIMARY KEY,
  img TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID
);

GRANT SELECT ON public.category_images TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.category_images TO authenticated;
GRANT ALL ON public.category_images TO service_role;

ALTER TABLE public.category_images ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view category images"
  ON public.category_images FOR SELECT
  USING (true);

CREATE POLICY "Admins can manage category images"
  ON public.category_images FOR ALL
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE TRIGGER category_images_updated_at
  BEFORE UPDATE ON public.category_images
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

ALTER PUBLICATION supabase_realtime ADD TABLE public.category_images;
