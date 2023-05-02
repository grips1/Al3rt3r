// $ cc `pkg-config --cflags gtk+-3.0` hello.c -o hello `pkg-config --libs gtk+-3.0`

#include <gtk/gtk.h>
#include <pcap.h>
static int capture_packet(/*GtkWidget *widget, gpointer   data*/void)
{
    //capture code for default enp0s3 interface
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* handler;
    struct pcap_pkthdr header;
    if((handler = pcap_open_live("enp0s3", 65535, 0, 20, error_buffer)) == NULL)
    {
        printf("\nHandler error:\n%s\n" , error_buffer);
        pcap_close(handler);
        return -1;
    }
    printf("Starting capture...\n");
    if((pcap_next(handler, &header)) == NULL)
    {
        printf("Failure capturing packet... :(\n");
        printf("Header length:\n%d\n", header.len); //header.len = length of packet!!! :O
        pcap_close(handler);
        return -1;
    }
    printf("Captured length:%d\n", header.len);
    pcap_close(handler);
    return 0;

}

static void activate (GtkApplication *app, gpointer user_data)
{
    GtkWidget *window;
    GtkWidget *button;
    GtkWidget *button_box;

    window = gtk_application_window_new (app);
    gtk_window_set_title (GTK_WINDOW (window), "Al3t3r");
    gtk_window_set_default_size (GTK_WINDOW (window), 500, 500);

    button_box = gtk_button_box_new (GTK_ORIENTATION_HORIZONTAL);
    gtk_container_add (GTK_CONTAINER (window), button_box);

    button = gtk_button_new_with_label ("Capture!");
    g_signal_connect (button, "clicked", G_CALLBACK (capture_packet), NULL); //button func
    g_signal_connect_swapped (button, "clicked", G_CALLBACK (gtk_widget_destroy), window);
    gtk_container_add (GTK_CONTAINER (button_box), button);
    gtk_widget_show_all (window);
}

int main(int argc, char **argv)
{
    GtkApplication *app;
    int status;
    app = gtk_application_new ("org.wtf.wtf", G_APPLICATION_FLAGS_NONE);
    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
    status = g_application_run (G_APPLICATION (app), argc, argv);
    g_object_unref (app);
    return status;
}